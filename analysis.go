package main
import (
	"archive/zip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)
func runAnalysisBackground(analysisID string, params map[string]interface{}, mode string) {
	analysisPath := filepath.Join("saved_analyses", analysisID+".json")
	defer func() {
		if r := recover(); r != nil {
			updateAnalysisStatus(analysisPath, "failed", fmt.Sprintf("%v", r))
		}
	}()
	var analyzedResults map[string]AnalysisResult
	switch mode {
	case "products":
		analyzedResults = runProductsAnalysis(params)
	case "folder":
		analyzedResults = runFolderAnalysis(params)
	case "cve":
		analyzedResults = runCVEBasedAnalysis(analysisID, params)
	case "cve_auto":
		analyzedResults = runCVEBasedAnalysis(analysisID, params)
	default:
		updateAnalysisStatus(analysisPath, "failed", "Unknown analysis mode")
		return
	}
	data, err := TrackedReadFile(analysisPath)
	if err != nil {
		return
	}
	TrackDiskRead(int64(len(data)))
	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		return
	}
	now := time.Now()
	analysis.Meta.Status = "completed"
	analysis.Meta.FinishedAt = &now
	analysis.Results = analyzedResults
	analysis.Meta.Params = params
	if params["enable_ai"] == "on" && config != nil {
		analysis.Meta.AIService = config.Service
		if svcConfig, ok := config.GetServiceConfig(config.Service); ok {
			if model, ok := svcConfig["model"].(string); ok {
				analysis.Meta.AIModel = model
			}
		}
		cveIDsStr := ""
		if cveIDs, ok := params["cve_ids"].(string); ok && cveIDs != "" {
			cveIDsStr = cveIDs
		}
		if cveIDsStr != "" && len(analyzedResults) > 0 {
			writeups := generateCVEWriteupsForResults(analyzedResults, cveIDsStr)
			if len(writeups) > 0 {
				analysis.CVEWriteups = writeups
			}
		}
	}
	updatedData, _ := json.MarshalIndent(analysis, "", "  ")
	TrackedWriteFile(analysisPath, updatedData, 0644)
	TrackDiskWrite(int64(len(updatedData)))
	InvalidateDashboardCache()
}
func runProductsAnalysis(params map[string]interface{}) map[string]AnalysisResult {
	os.MkdirAll("cache", 0755)
	TrackDiskWrite(100)
	cleanOldCache(30)
	if _, _, err := getCacheStats(); err == nil {
	}
	product, _ := params["product"].(string)
	oldVersion, _ := params["old_version"].(string)
	newVersion, _ := params["new_version"].(string)
	enableAIStr, _ := params["enable_ai"].(string)
	enableAI := enableAIStr == "on"
	cveIDs, _ := params["cve_ids"].(string)
	extension, _ := params["extension"].(string)
	specialKeywords, _ := params["special_keywords"].(string)
	products := loadProducts()
	productData, exists := products[product]
	if !exists {
		return make(map[string]AnalysisResult)
	}
	oldPath, err := downloadAndExtractVersion(productData.RepoURL, oldVersion)
	if err != nil {
		return make(map[string]AnalysisResult)
	}
	newPath, err := downloadAndExtractVersion(productData.RepoURL, newVersion)
	if err != nil {
		return make(map[string]AnalysisResult)
	}
	diffs := compareDirectories(oldPath, newPath, extension)
	results := analyzeDiffsForVulnerabilities(diffs, specialKeywords, cveIDs, enableAI)
	if enableAI && len(results) > 0 {
		results = runAIAnalysisOnResults(results, cveIDs, *aiThreads, newPath)
	}
	return results
}
func runLibraryAnalysis(params map[string]interface{}) map[string]AnalysisResult {
	os.MkdirAll("cache", 0755)
	cleanOldCache(30)
	if _, _, err := getCacheStats(); err == nil {
	}
	_ , _ = params["repo_name"].(string)
	repoURL, _ := params["repo_url"].(string)
	oldVersion, _ := params["old_version"].(string)
	newVersion, _ := params["new_version"].(string)
	enableAIStr, _ := params["enable_ai"].(string)
	enableAI := enableAIStr == "on"
	cveIDs, _ := params["cve_ids"].(string)
	extension, _ := params["extension"].(string)
	specialKeywords, _ := params["special_keywords"].(string)
	if repoURL == "" {
		return make(map[string]AnalysisResult)
	}
	oldPath, err := downloadAndExtractVersion(repoURL, oldVersion)
	if err != nil {
		return make(map[string]AnalysisResult)
	}
	newPath, err := downloadAndExtractVersion(repoURL, newVersion)
	if err != nil {
		return make(map[string]AnalysisResult)
	}
	diffs := compareDirectories(oldPath, newPath, extension)
	results := analyzeDiffsForVulnerabilities(diffs, specialKeywords, cveIDs, enableAI)
	if enableAI && len(results) > 0 {
		results = runAIAnalysisOnResults(results, cveIDs, *aiThreads, newPath)
	}
	return results
}
func downloadAndExtractVersion(repoURL, version string) (string, error) {
	cacheDir := "cache"
	os.MkdirAll(cacheDir, 0755)
	repoName := extractRepoName(repoURL)
	cacheKey := fmt.Sprintf("%s_%s", repoName, version)
	cachePath := filepath.Join(cacheDir, cacheKey)
	if _, err := os.Stat(cachePath); err == nil {
		TrackCacheHit()
		return cachePath, nil
	}
	TrackCacheMiss()
	downloadStartTime := time.Now()
	downloadURL := fmt.Sprintf("%s/archive/refs/tags/%s.zip", repoURL, version)
	resp, err := http.Get(downloadURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to download %s: status %d", version, resp.StatusCode)
	}
	tempDir, err := os.MkdirTemp(cacheDir, fmt.Sprintf("patchleaks_%s_", version))
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)
	zipPath := filepath.Join(tempDir, "version.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()
	_, err = TrackedCopy(zipFile, resp.Body)
	if err != nil {
		return "", err
	}
	extractPath := filepath.Join(tempDir, "extracted")
	err = extractZip(zipPath, extractPath)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(extractPath)
	if err != nil {
		return "", err
	}
	var sourcePath string
	for _, entry := range entries {
		if entry.IsDir() {
			sourcePath = filepath.Join(extractPath, entry.Name())
			break
		}
	}
	if sourcePath == "" {
		return "", fmt.Errorf("no directory found in extracted archive")
	}
	if err := os.Rename(sourcePath, cachePath); err != nil {
		if err := copyDirectory(sourcePath, cachePath); err != nil {
			return "", fmt.Errorf("failed to cache version: %v", err)
		}
	}
	downloadDuration := time.Since(downloadStartTime)
	TrackDownloadTime(downloadDuration)
	return cachePath, nil
}
func getCacheStats() (int, int64, error) {
	cacheDir := "cache"
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return 0, 0, err
	}
	count := 0
	var totalSize int64
	for _, entry := range entries {
		if entry.IsDir() {
			count++
			size, err := getDirSize(filepath.Join(cacheDir, entry.Name()))
			if err == nil {
				totalSize += size
			}
		}
	}
	return count, totalSize, nil
}
func getDirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}
func cleanOldCache(days int) error {
	cacheDir := "cache"
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return err
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			entryPath := filepath.Join(cacheDir, entry.Name())
			info, err := os.Stat(entryPath)
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				err := os.RemoveAll(entryPath)
				if err == nil {
					removed++
				}
			}
		}
	}
	if removed > 0 {
	}
	return nil
}
func extractRepoName(repoURL string) string {
	repoURL = strings.TrimSuffix(repoURL, "/")
	parts := strings.Split(repoURL, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return fmt.Sprintf("repo_%x", sha256.Sum256([]byte(repoURL)))[:8]
}
func copyDirectory(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}
		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()
		os.MkdirAll(filepath.Dir(dstPath), 0755)
		dstFile, err := os.Create(dstPath)
		if err != nil {
			return err
		}
		defer dstFile.Close()
		_, err = TrackedCopy(dstFile, srcFile)
		return err
	})
}
func extractZip(src, dest string) error {
	reader, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer reader.Close()
	os.MkdirAll(dest, 0755)
	for _, file := range reader.File {
		path := filepath.Join(dest, file.Name)
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.FileInfo().Mode())
			continue
		}
		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		os.MkdirAll(filepath.Dir(path), 0755)
		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			fileReader.Close()
			return err
		}
		_, err = TrackedCopy(targetFile, fileReader)
		fileReader.Close()
		targetFile.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
func compareDirectories(oldPath, newPath, extension string) []DiffFile {
	var diffs []DiffFile
	oldFiles := getFiles(oldPath)
	newFiles := getFiles(newPath)
	if len(oldFiles) > 0 {
		count := 0
		for _ = range oldFiles {
			if count < 5 {
				count++
			} else {
				break
			}
		}
		if len(oldFiles) > 5 {
		}
	}
	if len(newFiles) > 0 {
		count := 0
		for _ = range newFiles {
			if count < 5 {
				count++
			} else {
				break
			}
		}
		if len(newFiles) > 5 {
		}
	}
	commonFiles := intersect(oldFiles, newFiles)
	deletedFiles := subtract(oldFiles, newFiles)
	addedFiles := subtract(newFiles, oldFiles)
	if extension != "" {
		extensions := parseExtensions(extension)
		commonFiles = filterByExtensions(commonFiles, extensions)
		deletedFiles = filterByExtensions(deletedFiles, extensions)
		addedFiles = filterByExtensions(addedFiles, extensions)
	}
	modifiedCount := 0
	successfulDiffs := 0
	for i, file := range commonFiles {
		if i%1000 == 0 {
		}
		oldFilePath := filepath.Join(oldPath, file)
		newFilePath := filepath.Join(newPath, file)
		oldContent, err1 := TrackedReadFile(oldFilePath)
		newContent, err2 := TrackedReadFile(newFilePath)
		if err1 != nil || err2 != nil {
			continue
		}
		if string(oldContent) != string(newContent) {
			modifiedCount++
			diff := compareSingleFile(file, oldFilePath, newFilePath, "modified")
			if diff != nil {
				diffs = append(diffs, *diff)
				successfulDiffs++
			}
		}
	}
	for _, file := range deletedFiles {
		oldFilePath := filepath.Join(oldPath, file)
		diff := compareSingleFile(file, oldFilePath, "", "deleted")
		if diff != nil {
			diffs = append(diffs, *diff)
		}
	}
	for _, file := range addedFiles {
		newFilePath := filepath.Join(newPath, file)
		diff := compareSingleFile(file, "", newFilePath, "added")
		if diff != nil {
			diffs = append(diffs, *diff)
		}
	}
	return diffs
}
func getFiles(folder string) map[string]bool {
	files := make(map[string]bool)
	filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(folder, path)
		if err != nil {
			return nil
		}
		skipDirs := []string{".git", "node_modules", ".vscode", "__pycache__", ".idea", ".DS_Store"}
		for _, skipDir := range skipDirs {
			if strings.Contains(relPath, skipDir) {
				return nil
			}
		}
		if strings.HasPrefix(filepath.Base(relPath), ".") {
			return nil
		}
		files[relPath] = true
		return nil
	})
	return files
}
func intersect(set1, set2 map[string]bool) []string {
	var result []string
	for file := range set1 {
		if set2[file] {
			result = append(result, file)
		}
	}
	return result
}
func subtract(set1, set2 map[string]bool) []string {
	var result []string
	for file := range set1 {
		if !set2[file] {
			result = append(result, file)
		}
	}
	return result
}
func parseExtensions(extFilter string) []string {
	var extensions []string
	parts := strings.Split(extFilter, ",")
	for _, part := range parts {
		ext := strings.TrimSpace(part)
		if ext != "" {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			extensions = append(extensions, strings.ToLower(ext))
		}
	}
	return extensions
}
func filterByExtensions(files []string, extensions []string) []string {
	var result []string
	for _, file := range files {
		fileExt := strings.ToLower(filepath.Ext(file))
		for _, ext := range extensions {
			if fileExt == ext {
				result = append(result, file)
				break
			}
		}
	}
	return result
}
func compareSingleFile(filename, oldPath, newPath, fileType string) *DiffFile {
	if !validateFilename(filename) {
		return nil
	}
	switch fileType {
	case "deleted":
		if oldPath == "" || !fileExists(oldPath) {
			return nil
		}
		oldCode, err := readFileLines(oldPath)
		if err != nil || len(oldCode) == 0 {
			return nil
		}
		diff := []string{
			fmt.Sprintf("--- %s", oldPath),
			"+++ /dev/null",
			fmt.Sprintf("@@ -1,%d +0,0 @@", len(oldCode)),
		}
		for _, line := range oldCode {
			diff = append(diff, "-"+line)
		}
		return &DiffFile{
			Filename: filename,
			Diff:     diff,
			Type:     "deleted",
		}
	case "added":
		if newPath == "" || !fileExists(newPath) {
			return nil
		}
		newCode, err := readFileLines(newPath)
		if err != nil || len(newCode) == 0 {
			return nil
		}
		diff := []string{
			"--- /dev/null",
			fmt.Sprintf("+++ %s", newPath),
			fmt.Sprintf("@@ -0,0 +1,%d @@", len(newCode)),
		}
		for _, line := range newCode {
			diff = append(diff, "+"+line)
		}
		return &DiffFile{
			Filename: filename,
			Diff:     diff,
			Type:     "added",
		}
	case "modified":
		if oldPath == "" || newPath == "" || !fileExists(oldPath) || !fileExists(newPath) {
			return nil
		}
		oldCode, err1 := readFileLines(oldPath)
		newCode, err2 := readFileLines(newPath)
		if err1 != nil || err2 != nil {
			return nil
		}
		if len(oldCode) == 0 || len(newCode) == 0 {
			return nil
		}
		diff := generateUnifiedDiff(oldCode, newCode, oldPath, newPath)
		if len(diff) == 0 {
			return nil
		}
		return &DiffFile{
			Filename: filename,
			Diff:     diff,
			Type:     "modified",
		}
	}
	return nil
}
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
func readFileLines(filePath string) ([]string, error) {
	content, err := TrackedReadFile(filePath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines, nil
}
func validateFilename(filename string) bool {
	if filename == "" || len(filename) > 255 {
		return false
	}
	dangerous := []string{"..", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range dangerous {
		if strings.Contains(filename, char) {
			return false
		}
	}
	if strings.Contains(filename, "..") {
		return false
	}
	return true
}
func countByType(diffs []DiffFile, diffType string) int {
	count := 0
	for _, diff := range diffs {
		if diff.Type == diffType {
			count++
		}
	}
	return count
}
func generateUnifiedDiff(oldLines, newLines []string, oldPath, newPath string) []string {
	if len(oldLines) == 0 && len(newLines) == 0 {
		return []string{}
	}

	// Use the system diff command instead of difflib
	cmd := exec.Command("diff", "-u", oldPath, newPath)
	output, err := cmd.CombinedOutput()
	
	// diff returns exit code 1 when differences are found, which is expected
	if err != nil {
		// Check if it's just because differences were found (exit code 1)
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() != 1 {
				// Actual error, not just "files differ"
				return []string{}
			}
		} else {
			// Some other error occurred
			return []string{}
		}
	}
	
	// If no output, files are identical
	if len(output) == 0 {
		return []string{}
	}
	
	// Split output into lines
	diffStr := string(output)
	lines := strings.Split(diffStr, "\n")
	
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	
	return lines
}
func parseAIResponseForVulnerabilities(aiResponse string) string {
	lines := strings.Split(aiResponse, "\n")
	vulnCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "vulnerability existed: yes") {
			vulnCount++
		}
	}
	if vulnCount > 0 {
		return fmt.Sprintf("AI: %d vulnerabilities", vulnCount)
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "vulnerability existed: not sure") ||
			strings.Contains(strings.ToLower(line), "not sure") {
			return "AI: Not Sure"
		}
	}
	return "AI: No vulnerabilities"
}
func determineSeverityFromAIResponse(aiResponse string) string {
	lines := strings.Split(aiResponse, "\n")
	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(line, "vulnerability existed: yes") {
			if strings.Contains(line, "critical") || strings.Contains(line, "high") {
				return "high"
			} else if strings.Contains(line, "medium") {
				return "medium"
			} else if strings.Contains(line, "low") {
				return "low"
			}
			return "high"
		}
	}
	return "low"
}
func parseAICVEResponse(aiResponse string) string {
	lines := strings.Split(aiResponse, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "description matches: yes") {
			return "Yes"
		}
		if strings.Contains(lineLower, "description matches: no") {
			return "No"
		}
		if strings.Contains(lineLower, "matches: yes") || strings.Contains(lineLower, "match: yes") {
			return "Yes"
		}
		if strings.Contains(lineLower, "matches: no") || strings.Contains(lineLower, "match: no") {
			return "No"
		}
	}
	return "No"
}
func analyzeDiffsForVulnerabilities(diffs []DiffFile, keywords, cveIDs string, enableAI bool) map[string]AnalysisResult {
	results := make(map[string]AnalysisResult)
	for _, diff := range diffs {
		if !validateFilename(diff.Filename) {
			continue
		}
		contextLines := diff.Diff
		if len(contextLines) > 1000 {
			contextLines = contextLines[:1000]
		}
		result := AnalysisResult{
			Context: contextLines,
		}
		if enableAI {
			result.VulnerabilityStatus = "AI: Analyzing..."
		}
		result.VulnSeverity = "unknown"
		results[diff.Filename] = result
	}
	return results
}
func runAIAnalysisOnResults(results map[string]AnalysisResult, cveIDs string, threadCount int, newPath string) map[string]AnalysisResult {
	if config == nil {
		return results
	}
	if threadCount < 1 {
		threadCount = 1
	}
	type workItem struct {
		filename string
		result   AnalysisResult
	}
	var workItems []workItem
	for filename, result := range results {
		if result.AIResponse == "" {
			workItems = append(workItems, workItem{filename, result})
		}
	}
	if len(workItems) == 0 {
		return results
	}
	cveDescriptionCache := make(map[string]string)
	if cveIDs != "" {
		cveList := strings.Split(cveIDs, ",")
		for _, cveID := range cveList {
			cveID = strings.TrimSpace(cveID)
			if cveID != "" {
				description := GetCVEDescription(cveID)
				cveDescriptionCache[cveID] = description
			}
		}
	}
	workChan := make(chan workItem, len(workItems))
	resultChan := make(chan workItem, len(workItems))
	var wg sync.WaitGroup
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			IncrementActiveAIThreads()
			defer DecrementActiveAIThreads()
			for item := range workChan {
				ThrottleYield()
				diffContent := strings.Join(item.result.Context, "\n")
				enhancedDiff := diffContent
				filePath := filepath.Join(newPath, item.filename)
				functionContext, err := ExtractFunctionContext(filePath, diffContent, true, newPath)
				enableContext := true
				if config != nil && config.Parameters != nil {
					if val, ok := config.Parameters["enable_context_analysis"]; ok {
						if enabled, ok := val.(bool); ok {
							enableContext = enabled
						}
					}
				}
				if enableContext && err == nil && functionContext != "" {
					enhancedDiff = functionContext + diffContent
				}
				aiResponse := GetAIAnalysis(item.filename, enhancedDiff)
				item.result.AIResponse = aiResponse
				if cveIDs != "" {
					cveList := strings.Split(cveIDs, ",")
					if item.result.CVEMatches == nil {
						item.result.CVEMatches = make(map[string]CVEMatch)
					}
					for _, cveID := range cveList {
						cveID = strings.TrimSpace(cveID)
						if cveID != "" {
							description, exists := cveDescriptionCache[cveID]
							if !exists {
								description = "CVE description not available"
							}
							cveAnalysis := AnalyzeWithCVE(item.result.AIResponse, description)
							cveResult := parseAICVEResponse(cveAnalysis)
							item.result.CVEMatches[cveID] = CVEMatch{
								Result:      cveResult,
								Description: description,
							}
						}
					}
				}
				item.result.VulnerabilityStatus = parseAIResponseForVulnerabilities(aiResponse)
				item.result.VulnSeverity = determineSeverityFromAIResponse(aiResponse)
				resultChan <- item
			}
		}(i)
	}
	go func() {
	for _, item := range workItems {
			workChan <- item
		}
		close(workChan)
	}()
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	completedCount := 0
	for item := range resultChan {
		results[item.filename] = item.result
		completedCount++
		if completedCount%10 == 0 || completedCount == len(workItems) {
		}
	}
	if cveIDs != "" {
		generateCVEWriteupsForResults(results, cveIDs)
	}
	return results
}
func generateCVEWriteupsForResults(results map[string]AnalysisResult, cveIDs string) map[string]string {
	writeups := make(map[string]string)
	cveList := strings.Split(cveIDs, ",")
	for _, cveID := range cveList {
		cveID = strings.TrimSpace(cveID)
		if cveID == "" {
			continue
		}
		var matchingAnalyses []string
		var cveDescription string
		for filename, result := range results {
			if result.CVEMatches != nil {
				if cveMatch, exists := result.CVEMatches[cveID]; exists && cveMatch.Result == "Yes" {
					if cveDescription == "" {
						cveDescription = cveMatch.Description
					}
					fileAnalysis := fmt.Sprintf("File: %s\n\nAI Analysis:\n%s", filename, result.AIResponse)
					matchingAnalyses = append(matchingAnalyses, fileAnalysis)
				}
			}
		}
		if len(matchingAnalyses) > 0 {
			writeup := GenerateCVEWriteup(cveID, cveDescription, matchingAnalyses)
			writeups[cveID] = writeup
		}
	}
	if len(writeups) > 0 {
	}
	return writeups
}
func runFolderAnalysis(params map[string]interface{}) map[string]AnalysisResult {
	oldFolder, _ := params["old_folder"].(string)
	newFolder, _ := params["new_folder"].(string)
	extension, _ := params["extension"].(string)
	specialKeywords, _ := params["special_keywords"].(string)
	enableAI, _ := params["enable_ai"].(string)
	cveIDs, _ := params["cve_ids"].(string)
	var keywords []string
	if specialKeywords != "" {
		keywords = strings.Split(specialKeywords, ",")
	}
	diffs := compareFolders(oldFolder, newFolder, extension, keywords)
	results := analyzeDiffsWithKeywords(diffs, keywords, enableAI == "on")
	if enableAI == "on" && len(results) > 0 {
		results = runAIAnalysisOnResults(results, cveIDs, *aiThreads, newFolder)
	}
	return results
}
func compareFolders(oldFolder, newFolder, extFilter string, keywords []string) []DiffFile {
	oldFiles := getFilesRecursive(oldFolder)
	newFiles := getFilesRecursive(newFolder)
	commonFiles := intersectFiles(oldFiles, newFiles)
	deletedFiles := subtractFiles(oldFiles, newFiles)
	addedFiles := subtractFiles(newFiles, oldFiles)
	if extFilter != "" {
		exts := parseExtensions(extFilter)
		commonFiles = filterByExtensions(commonFiles, exts)
		deletedFiles = filterByExtensions(deletedFiles, exts)
		addedFiles = filterByExtensions(addedFiles, exts)
	}
	var diffs []DiffFile
	for _, file := range commonFiles {
		oldPath := filepath.Join(oldFolder, file)
		newPath := filepath.Join(newFolder, file)
		oldLines, _ := readFileLines(oldPath)
		newLines, _ := readFileLines(newPath)
		if len(oldLines) == 0 && len(newLines) == 0 {
			continue
		}
		diffLines := generateUnifiedDiff(oldLines, newLines, oldPath, newPath)
		if len(diffLines) > 0 {
			if shouldIncludeDiff(diffLines, keywords) {
				diffs = append(diffs, DiffFile{
					Filename: file,
					Diff:     diffLines,
					Type:     "modified",
				})
			}
		}
	}
	for _, file := range deletedFiles {
		oldPath := filepath.Join(oldFolder, file)
		oldLines, _ := readFileLines(oldPath)
		if len(oldLines) > 0 {
			if shouldIncludeFile(oldLines, keywords) {
				diffLines := []string{
					fmt.Sprintf("--- %s", oldPath),
					"+++ /dev/null",
					fmt.Sprintf("@@ -1,%d +0,0 @@", len(oldLines)),
				}
				for _, line := range oldLines {
					diffLines = append(diffLines, "-"+line)
				}
				diffs = append(diffs, DiffFile{
					Filename: file,
					Diff:     diffLines,
					Type:     "deleted",
				})
			}
		}
	}
	for _, entry := range addedFiles {
		file := entry
		newPath := filepath.Join(newFolder, file)
		newLines, _ := readFileLines(newPath)
		if len(newLines) > 0 {
			if shouldIncludeFile(newLines, keywords) {
				diffLines := []string{
					"--- /dev/null",
					fmt.Sprintf("+++ %s", newPath),
					fmt.Sprintf("@@ -0,0 +1,%d @@", len(newLines)),
				}
				for _, line := range newLines {
					diffLines = append(diffLines, "+"+line)
				}
				diffs = append(diffs, DiffFile{
					Filename: file,
					Diff:     diffLines,
					Type:     "added",
				})
			}
		}
	}
	return diffs
}
func getFilesRecursive(folder string) []string {
	var files []string
	filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			relPath, _ := filepath.Rel(folder, path)
			files = append(files, relPath)
		}
		return nil
	})
	return files
}
func intersectFiles(a, b []string) []string {
	set := make(map[string]bool)
	for _, entry := range b {
		set[entry] = true
	}
	var result []string
	for _, entry := range a {
		if set[entry] {
			result = append(result, entry)
		}
	}
	return result
}
func subtractFiles(a, b []string) []string {
	set := make(map[string]bool)
	for _, entry := range b {
		set[entry] = true
	}
	var result []string
	for _, entry := range a {
		if !set[entry] {
			result = append(result, entry)
		}
	}
	return result
}
func shouldIncludeDiff(diffLines []string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, line := range diffLines {
		for _, keyword := range keywords {
			if strings.Contains(line, strings.TrimSpace(keyword)) {
				return true
			}
		}
	}
	return false
}
func shouldIncludeFile(lines []string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, line := range lines {
		for _, keyword := range keywords {
			if strings.Contains(line, strings.TrimSpace(keyword)) {
				return true
			}
		}
	}
	return false
}
func analyzeDiffsWithKeywords(diffs []DiffFile, keywords []string, enableAI bool) map[string]AnalysisResult {
	results := make(map[string]AnalysisResult)
	for _, diff := range diffs {
		contextLines := diff.Diff
		if len(contextLines) > 1000 {
			contextLines = contextLines[:1000]
		}
		result := AnalysisResult{
			Context:      contextLines,
			VulnSeverity: "unknown",
		}
		if enableAI {
			result.VulnerabilityStatus = "AI: Analyzing..."
		}
		results[diff.Filename] = result
	}
	return results
}
func processAIAnalysis(results map[string]AnalysisResult, diffs []DiffFile, cveIDs string) map[string]AnalysisResult {
	if config == nil {
		return results
	}
	for _, diff := range diffs {
		if _, exists := results[diff.Filename]; !exists {
			continue
		}
		result := results[diff.Filename]
		diffContent := strings.Join(result.Context, "\n")
		aiResponse := GetAIAnalysis(diff.Filename, diffContent)
		result.AIResponse = aiResponse
		if cveIDs != "" {
			cveMatches := make(map[string]CVEMatch)
			for _, cveID := range strings.Split(cveIDs, ",") {
				cveID = strings.TrimSpace(cveID)
				if cveID == "" {
					continue
				}
				cveDescription := GetCVEDescription(cveID)
				cveAnalysis := AnalyzeWithCVE(aiResponse, cveDescription)
				match := "Unknown"
				if strings.Contains(strings.ToLower(cveAnalysis), "description matches: yes") {
					match = "Yes"
				} else if strings.Contains(strings.ToLower(cveAnalysis), "description matches: no") {
					match = "No"
				}
				cveMatches[cveID] = CVEMatch{
					Result:      match,
					Description: cveDescription,
				}
			}
			result.CVEMatches = cveMatches
		}
		vulnStatus := "AI: No vulnerabilities"
		severity := "no"
		if strings.Contains(strings.ToLower(aiResponse), "vulnerability existed") {
			yesCount := strings.Count(strings.ToLower(aiResponse), "yes")
			if yesCount > 0 {
				vulnStatus = fmt.Sprintf("AI: %d vulnerabilities", yesCount)
				severity = "yes"
			} else if strings.Contains(strings.ToLower(aiResponse), "not sure") {
				vulnStatus = "AI: Not sure"
				severity = "not sure"
			}
		}
		result.VulnerabilityStatus = vulnStatus
		result.VulnSeverity = severity
		results[diff.Filename] = result
	}
	return results
}
func updateAnalysisStatus(analysisPath, status, errorMsg string) {
	data, err := TrackedReadFile(analysisPath)
	if err != nil {
		return
	}
	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		return
	}
	analysis.Meta.Status = status
	if errorMsg != "" {
		analysis.Meta.Error = errorMsg
	}
	updatedData, _ := json.MarshalIndent(analysis, "", "  ")
	TrackedWriteFile(analysisPath, updatedData, 0644)
}
