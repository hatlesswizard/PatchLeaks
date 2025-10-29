package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
			log.Printf("Analysis %s panicked: %v", analysisID, r)
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

	data, err := os.ReadFile(analysisPath)
	if err != nil {
		log.Printf("Failed to read analysis file: %v", err)
		return
	}

	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		log.Printf("Failed to unmarshal analysis: %v", err)
		return
	}

	analysis.Meta.Status = "completed"
	analysis.Results = analyzedResults
	
	analysis.Meta.Params = params

	if params["enable_ai"] == "on" && config != nil {
		analysis.Meta.AIService = config.Service
		if svcConfig, ok := config.GetServiceConfig(config.Service); ok {
			if model, ok := svcConfig["model"].(string); ok {
				analysis.Meta.AIModel = model
			}
		}
	}

	updatedData, _ := json.MarshalIndent(analysis, "", "  ")
	os.WriteFile(analysisPath, updatedData, 0644)

	log.Printf("Analysis %s completed successfully", analysisID)
}

func runProductsAnalysis(params map[string]interface{}) map[string]AnalysisResult {
	log.Printf("Running REAL products analysis with params: %v", params)
	
	os.MkdirAll("cache", 0755)
	cleanOldCache(30)
	
	if count, size, err := getCacheStats(); err == nil {
		log.Printf("Cache stats: %d versions, %.2f MB", count, float64(size)/(1024*1024))
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
		log.Printf("Product %s not found", product)
		return make(map[string]AnalysisResult)
	}
	
	log.Printf("Analyzing %s: %s → %s (AI enabled: %v)", product, oldVersion, newVersion, enableAI)
	
	oldPath, err := downloadAndExtractVersion(productData.RepoURL, oldVersion)
	if err != nil {
		log.Printf("Failed to download old version %s: %v", oldVersion, err)
		return make(map[string]AnalysisResult)
	}
	
	newPath, err := downloadAndExtractVersion(productData.RepoURL, newVersion)
	if err != nil {
		log.Printf("Failed to download new version %s: %v", newVersion, err)
		return make(map[string]AnalysisResult)
	}
	
	
	var oldIndex, newIndex *FunctionIndex
	if enableAI {
		log.Printf("Indexing PHP files for function definitions...")
		oldIndex, _ = ensureIndexed(oldPath)
		newIndex, _ = ensureIndexed(newPath)
		if oldIndex != nil || newIndex != nil {
			oldCount := 0
			newCount := 0
			if oldIndex != nil {
				oldCount = len(oldIndex.Classes)
			}
			if newIndex != nil {
				newCount = len(newIndex.Classes)
			}
			log.Printf("✅ PHP indexing complete (old: %d classes, new: %d classes)", oldCount, newCount)
		}
	}
	
	diffs := compareDirectories(oldPath, newPath, extension)
	log.Printf("Found %d file differences", len(diffs))
	
	results := analyzeDiffsForVulnerabilities(diffs, specialKeywords, cveIDs)
	
	if enableAI && len(results) > 0 {
		results = runAIAnalysisOnResults(results, cveIDs, *aiThreads, oldPath, newPath, oldIndex, newIndex)
	}
	
	log.Printf("Analysis complete: %d files with potential issues", len(results))
	return results
}

func runLibraryAnalysis(params map[string]interface{}) map[string]AnalysisResult {
	log.Printf("Running library analysis with params: %v", params)
	
	os.MkdirAll("cache", 0755)
	cleanOldCache(30)
	
	if count, size, err := getCacheStats(); err == nil {
		log.Printf("Cache stats: %d versions, %.2f MB", count, float64(size)/(1024*1024))
	}
	
	repoName, _ := params["repo_name"].(string)
	repoURL, _ := params["repo_url"].(string)
	oldVersion, _ := params["old_version"].(string)
	newVersion, _ := params["new_version"].(string)
	enableAIStr, _ := params["enable_ai"].(string)
	enableAI := enableAIStr == "on"
	cveIDs, _ := params["cve_ids"].(string)
	extension, _ := params["extension"].(string)
	specialKeywords, _ := params["special_keywords"].(string)
	
	if repoURL == "" {
		log.Printf("Repository URL not provided")
		return make(map[string]AnalysisResult)
	}
	
	log.Printf("Analyzing %s: %s → %s (AI enabled: %v)", repoName, oldVersion, newVersion, enableAI)
	
	oldPath, err := downloadAndExtractVersion(repoURL, oldVersion)
	if err != nil {
		log.Printf("Failed to download old version %s: %v", oldVersion, err)
		return make(map[string]AnalysisResult)
	}
	
	newPath, err := downloadAndExtractVersion(repoURL, newVersion)
	if err != nil {
		log.Printf("Failed to download new version %s: %v", newVersion, err)
		return make(map[string]AnalysisResult)
	}
	
	
	var oldIndex, newIndex *FunctionIndex
	if enableAI {
		log.Printf("Indexing PHP files for function definitions...")
		oldIndex, _ = ensureIndexed(oldPath)
		newIndex, _ = ensureIndexed(newPath)
		if oldIndex != nil || newIndex != nil {
			oldCount := 0
			newCount := 0
			if oldIndex != nil {
				oldCount = len(oldIndex.Classes)
			}
			if newIndex != nil {
				newCount = len(newIndex.Classes)
			}
			log.Printf("✅ PHP indexing complete (old: %d classes, new: %d classes)", oldCount, newCount)
		}
	}
	
	diffs := compareDirectories(oldPath, newPath, extension)
	log.Printf("Found %d file differences", len(diffs))
	
	results := analyzeDiffsForVulnerabilities(diffs, specialKeywords, cveIDs)
	
	if enableAI && len(results) > 0 {
		results = runAIAnalysisOnResults(results, cveIDs, *aiThreads, oldPath, newPath, oldIndex, newIndex)
	}
	
	log.Printf("Library analysis complete: %d files with potential issues", len(results))
	return results
}

func downloadAndExtractVersion(repoURL, version string) (string, error) {
	cacheDir := "cache"
	os.MkdirAll(cacheDir, 0755)
	
	repoName := extractRepoName(repoURL)
	cacheKey := fmt.Sprintf("%s_%s", repoName, version)
	cachePath := filepath.Join(cacheDir, cacheKey)
	
	if _, err := os.Stat(cachePath); err == nil {
		log.Printf("Using cached version: %s (%s)", version, cachePath)
		return cachePath, nil
	}
	
	log.Printf("Downloading and caching %s from %s", version, repoURL)
	
	downloadURL := fmt.Sprintf("%s/archive/refs/tags/%s.zip", repoURL, version)
	
	resp, err := http.Get(downloadURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to download %s: status %d", version, resp.StatusCode)
	}
	
	tempDir, err := os.MkdirTemp("", fmt.Sprintf("patchleaks_%s_%s", version, "temp"))
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
	
	_, err = io.Copy(zipFile, resp.Body)
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
	
	err = copyDirectory(sourcePath, cachePath)
	if err != nil {
		return "", fmt.Errorf("failed to cache version: %v", err)
	}
	
	log.Printf("Cached version %s to %s", version, cachePath)
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
					log.Printf("Removed old cache: %s", entry.Name())
				}
			}
		}
	}
	
	if removed > 0 {
		log.Printf("Cleaned up %d old cached versions", removed)
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
		
		_, err = io.Copy(dstFile, srcFile)
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
		
		_, err = io.Copy(targetFile, fileReader)
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
	
	log.Printf("Comparing directories: %s vs %s", oldPath, newPath)
	
	oldFiles := getFiles(oldPath)
	newFiles := getFiles(newPath)
	
	log.Printf("Found %d files in old version, %d files in new version", len(oldFiles), len(newFiles))
	
	if len(oldFiles) > 0 {
		count := 0
		log.Printf("Sample files in old version:")
		for file := range oldFiles {
			if count < 5 {
				log.Printf("  - %s", file)
				count++
			} else {
				break
			}
		}
		if len(oldFiles) > 5 {
			log.Printf("  ... and %d more files", len(oldFiles)-5)
		}
	}
	
	if len(newFiles) > 0 {
		count := 0
		log.Printf("Sample files in new version:")
		for file := range newFiles {
			if count < 5 {
				log.Printf("  - %s", file)
				count++
			} else {
				break
			}
		}
		if len(newFiles) > 5 {
			log.Printf("  ... and %d more files", len(newFiles)-5)
		}
	}
	
	commonFiles := intersect(oldFiles, newFiles)
	deletedFiles := subtract(oldFiles, newFiles)
	addedFiles := subtract(newFiles, oldFiles)
	
	log.Printf("Files: %d common, %d deleted, %d added", len(commonFiles), len(deletedFiles), len(addedFiles))
	
	if extension != "" {
		extensions := parseExtensions(extension)
		commonFiles = filterByExtensions(commonFiles, extensions)
		deletedFiles = filterByExtensions(deletedFiles, extensions)
		addedFiles = filterByExtensions(addedFiles, extensions)
		log.Printf("After extension filter: %d common, %d deleted, %d added", len(commonFiles), len(deletedFiles), len(addedFiles))
	}
	
	log.Printf("Processing %d common files for modifications...", len(commonFiles))
	modifiedCount := 0
	successfulDiffs := 0
	for i, file := range commonFiles {
		if i%1000 == 0 {
			log.Printf("Processed %d/%d common files...", i, len(commonFiles))
		}
		
		oldFilePath := filepath.Join(oldPath, file)
		newFilePath := filepath.Join(newPath, file)
		
		oldContent, err1 := os.ReadFile(oldFilePath)
		newContent, err2 := os.ReadFile(newFilePath)
		
		if err1 != nil || err2 != nil {
			log.Printf("Error reading files %s: old=%v, new=%v", file, err1, err2)
			continue
		}
		
		if string(oldContent) != string(newContent) {
			modifiedCount++
			log.Printf("File %s is different (size: old=%d, new=%d)", file, len(oldContent), len(newContent))
			
			diff := compareSingleFile(file, oldFilePath, newFilePath, "modified")
			if diff != nil {
				diffs = append(diffs, *diff)
				successfulDiffs++
				log.Printf("✅ Generated diff for %s with %d lines (total diffs: %d)", file, len(diff.Diff), len(diffs))
			} else {
				log.Printf("❌ Failed to generate diff for %s", file)
			}
		}
	}
	log.Printf("Found %d modified files out of %d common files, generated %d successful diffs", modifiedCount, len(commonFiles), successfulDiffs)
	
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
	
	log.Printf("Generated %d file differences: %d modified, %d added, %d deleted", 
		len(diffs), 
		countByType(diffs, "modified"),
		countByType(diffs, "added"), 
		countByType(diffs, "deleted"))
	
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
	log.Printf("DEBUG: compareSingleFile called for %s (type: %s)", filename, fileType)
	
	if !validateFilename(filename) {
		log.Printf("DEBUG: Filename validation failed for %s", filename)
		return nil
	}
	
	switch fileType {
	case "deleted":
		if oldPath == "" || !fileExists(oldPath) {
			log.Printf("DEBUG: Deleted file check failed for %s (path: %s, exists: %v)", filename, oldPath, fileExists(oldPath))
			return nil
		}
		
		oldCode, err := readFileLines(oldPath)
		if err != nil || len(oldCode) == 0 {
			log.Printf("DEBUG: Failed to read deleted file %s: err=%v, lines=%d", filename, err, len(oldCode))
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
		
		log.Printf("DEBUG: Generated deleted diff for %s with %d lines", filename, len(diff))
		return &DiffFile{
			Filename: filename,
			Diff:     diff,
			Type:     "deleted",
		}
		
	case "added":
		if newPath == "" || !fileExists(newPath) {
			log.Printf("DEBUG: Added file check failed for %s (path: %s, exists: %v)", filename, newPath, fileExists(newPath))
			return nil
		}
		
		newCode, err := readFileLines(newPath)
		if err != nil || len(newCode) == 0 {
			log.Printf("DEBUG: Failed to read added file %s: err=%v, lines=%d", filename, err, len(newCode))
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
		
		log.Printf("DEBUG: Generated added diff for %s with %d lines", filename, len(diff))
		return &DiffFile{
			Filename: filename,
			Diff:     diff,
			Type:     "added",
		}
		
	case "modified":
		if oldPath == "" || newPath == "" || !fileExists(oldPath) || !fileExists(newPath) {
			log.Printf("DEBUG: Modified file check failed for %s (old: %s, new: %s, old_exists: %v, new_exists: %v)", 
				filename, oldPath, newPath, fileExists(oldPath), fileExists(newPath))
			return nil
		}
		
		oldCode, err1 := readFileLines(oldPath)
		newCode, err2 := readFileLines(newPath)
		
		if err1 != nil || err2 != nil {
			log.Printf("DEBUG: Failed to read modified file %s: old_err=%v, new_err=%v", filename, err1, err2)
			return nil
		}
		
		if len(oldCode) == 0 || len(newCode) == 0 {
			log.Printf("DEBUG: Empty file content for %s: old_lines=%d, new_lines=%d", filename, len(oldCode), len(newCode))
			return nil
		}
		
		diff := generateUnifiedDiff(oldCode, newCode, oldPath, newPath)
		if len(diff) == 0 {
			log.Printf("DEBUG: Empty diff generated for %s", filename)
			return nil
		}
		
		log.Printf("DEBUG: Generated modified diff for %s with %d lines", filename, len(diff))
		return &DiffFile{
			Filename: filename,
			Diff:     diff,
			Type:     "modified",
		}
	}
	
	log.Printf("DEBUG: Unknown file type %s for %s", fileType, filename)
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func readFileLines(filePath string) ([]string, error) {
	content, err := os.ReadFile(filePath)
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

type FileInfo struct {
	Path string
	Hash string
}

func getAllFiles(rootPath, extension string) map[string]FileInfo {
	files := make(map[string]FileInfo)
	
	filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if info.IsDir() {
			return nil
		}
		
		if extension != "" && !strings.HasSuffix(path, extension) {
			return nil
		}
		
		skipDirs := []string{".git", "node_modules", ".vscode", "__pycache__", "vendor"}
		for _, skipDir := range skipDirs {
			if strings.Contains(path, skipDir) {
				return nil
			}
		}
		
		relPath, _ := filepath.Rel(rootPath, path)
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		
		hash := fmt.Sprintf("%x", sha256.Sum256(content))
		files[relPath] = FileInfo{
			Path: path,
			Hash: hash,
		}
		
		return nil
	})
	
	return files
}

func generateUnifiedDiff(oldLines, newLines []string, oldPath, newPath string) []string {
	log.Printf("DEBUG: generateUnifiedDiff called for %s (old: %d lines, new: %d lines)", filepath.Base(oldPath), len(oldLines), len(newLines))
	
	oldTempFile, err := os.CreateTemp("", "old-*.txt")
	if err != nil {
		log.Printf("Failed to create temp file for old content: %v", err)
		return []string{}
	}
	defer os.Remove(oldTempFile.Name())
	defer oldTempFile.Close()
	
	newTempFile, err := os.CreateTemp("", "new-*.txt")
	if err != nil {
		log.Printf("Failed to create temp file for new content: %v", err)
		return []string{}
	}
	defer os.Remove(newTempFile.Name())
	defer newTempFile.Close()
	
	for _, line := range oldLines {
		oldTempFile.WriteString(line + "\n")
	}
	oldTempFile.Close()
	
	for _, line := range newLines {
		newTempFile.WriteString(line + "\n")
	}
	newTempFile.Close()
	
	cmd := exec.Command("diff", "-u", oldTempFile.Name(), newTempFile.Name())
	output, err := cmd.CombinedOutput()
	
	if err != nil && cmd.ProcessState.ExitCode() != 1 {
		log.Printf("diff command failed: %v", err)
		return []string{}
	}
	
	lines := strings.Split(string(output), "\n")
	
	var result []string
	for _, line := range lines {
		if strings.HasPrefix(line, "---") {
			result = append(result, fmt.Sprintf("--- %s", oldPath))
		} else if strings.HasPrefix(line, "+++") {
			result = append(result, fmt.Sprintf("+++ %s", newPath))
		} else {
			result = append(result, line)
		}
	}
	
	log.Printf("DEBUG: Generated diff with %d lines using system diff command", len(result))
	return result
}



func computeDiff(old, new []string, filename string) []string {
	var result []string
	
	result = append(result, fmt.Sprintf("--- a/%s", filename))
	result = append(result, fmt.Sprintf("+++ b/%s", filename))
	
	commonPrefix := 0
	for commonPrefix < len(old) && commonPrefix < len(new) && old[commonPrefix] == new[commonPrefix] {
		commonPrefix++
	}
	
	commonSuffix := 0
	for commonSuffix < len(old)-commonPrefix && commonSuffix < len(new)-commonPrefix && 
		old[len(old)-1-commonSuffix] == new[len(new)-1-commonSuffix] {
		commonSuffix++
	}
	
	oldMiddle := old[commonPrefix : len(old)-commonSuffix]
	newMiddle := new[commonPrefix : len(new)-commonSuffix]
	
	oldStart := commonPrefix + 1
	oldCount := len(oldMiddle)
	newStart := commonPrefix + 1
	newCount := len(newMiddle)
	
	result = append(result, fmt.Sprintf("@@ -%d,%d +%d,%d @@", oldStart, oldCount, newStart, newCount))
	
	if commonPrefix > 0 {
		contextStart := max(0, commonPrefix-3)
		for i := contextStart; i < commonPrefix; i++ {
			result = append(result, "  "+old[i])
		}
	}
	
	if len(oldMiddle) > 0 || len(newMiddle) > 0 {
		maxLines := max(len(oldMiddle), len(newMiddle))
		
		for i := 0; i < maxLines; i++ {
			var oldLine, newLine string
			if i < len(oldMiddle) {
				oldLine = oldMiddle[i]
			}
			if i < len(newMiddle) {
				newLine = newMiddle[i]
			}
			
			if oldLine == newLine {
				result = append(result, "  "+oldLine)
			} else {
				if oldLine != "" {
					result = append(result, "- "+oldLine)
				}
				if newLine != "" {
					result = append(result, "+ "+newLine)
				}
			}
		}
	}
	
	if commonSuffix > 0 {
		contextEnd := min(len(old), commonPrefix+len(oldMiddle)+3)
		for i := commonPrefix + len(oldMiddle); i < contextEnd; i++ {
			result = append(result, "  "+old[i])
		}
	}
	
	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

func analyzeDiffsForVulnerabilities(diffs []DiffFile, keywords, cveIDs string) map[string]AnalysisResult {
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
		
		result.VulnerabilityStatus = "AI: Analyzing..."
		result.VulnSeverity = "unknown"
		
		results[diff.Filename] = result
	}
	
	return results
}

func runAIAnalysisOnResults(results map[string]AnalysisResult, cveIDs string, threadCount int, oldPath, newPath string, oldIndex, newIndex *FunctionIndex) map[string]AnalysisResult {
	log.Printf("Running REAL AI analysis on %d results with %d threads...", len(results), threadCount)
	
	if config == nil {
		log.Printf("❌ AI config is nil - AI analysis will not work!")
		return results
	}
	if svcConfig, ok := config.GetServiceConfig(config.Service); ok {
		if model, ok := svcConfig["model"].(string); ok {
			log.Printf("✅ AI config loaded: service=%s, model=%s", config.Service, model)
		} else {
			log.Printf("✅ AI config loaded: service=%s", config.Service)
		}
	} else {
		log.Printf("✅ AI config loaded: service=%s", config.Service)
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
		log.Printf("No files need AI analysis")
		return results
	}
	if len(workItems) == 0 {
		log.Printf("No files need AI analysis")
		return results
	}
	
	log.Printf("Processing %d files with %d threads", len(workItems), threadCount)
	
	workChan := make(chan workItem, len(workItems))
	resultChan := make(chan workItem, len(workItems))
	
	var wg sync.WaitGroup
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			log.Printf("Worker %d started", workerID+1)
			
			for item := range workChan {
				diffContent := strings.Join(item.result.Context, "\n")
				
				
				enhancedDiff := diffContent
				if oldIndex != nil || newIndex != nil {
					if strings.HasSuffix(strings.ToLower(item.filename), ".php") {
						calls := extractFunctionCallsFromDiff(diffContent, item.filename)
						definitions := lookupFunctionDefinitions(calls, oldIndex, newIndex, item.filename)
						if len(definitions) > 0 {
							enhancedDiff = enhanceAIPromptWithFunctions(diffContent, definitions)
							log.Printf("Worker %d: Enhanced diff with %d function definitions for %s", workerID+1, len(definitions), item.filename)
						}
					}
				}
				
				log.Printf("Worker %d: Calling AI analysis for %s...", workerID+1, item.filename)
				aiResponse := GetAIAnalysis(item.filename, enhancedDiff)
				log.Printf("Worker %d: AI response for %s: %s", workerID+1, item.filename, aiResponse[:min(100, len(aiResponse))])
				item.result.AIResponse = aiResponse
				
				if cveIDs != "" {
					cveList := strings.Split(cveIDs, ",")
					if item.result.CVEMatches == nil {
						item.result.CVEMatches = make(map[string]CVEMatch)
					}
					for _, cveID := range cveList {
						cveID = strings.TrimSpace(cveID)
						if cveID != "" {
							log.Printf("Worker %d: Running AI CVE analysis for %s...", workerID+1, cveID)
							
							description := GetCVEDescription(cveID)
							log.Printf("Worker %d: CVE description: %s", workerID+1, description[:min(100, len(description))])
							
							if item.result.AIResponse == "" {
								item.result.AIResponse = GetAIAnalysis(item.filename, enhancedDiff)
								log.Printf("Worker %d: AI analysis: %s", workerID+1, item.result.AIResponse[:min(100, len(item.result.AIResponse))])
							}
							
							cveAnalysis := AnalyzeWithCVE(item.result.AIResponse, description)
							log.Printf("Worker %d: AI CVE analysis: %s", workerID+1, cveAnalysis[:min(100, len(cveAnalysis))])
							
							cveResult := parseAICVEResponse(cveAnalysis)
							
							item.result.CVEMatches[cveID] = CVEMatch{
								Result:      cveResult,
								Description: description,
							}
							log.Printf("Worker %d: CVE %s result: %s", workerID+1, cveID, cveResult)
						}
					}
				}
				
				item.result.VulnerabilityStatus = parseAIResponseForVulnerabilities(aiResponse)
				item.result.VulnSeverity = determineSeverityFromAIResponse(aiResponse)
				
				resultChan <- item
				log.Printf("Worker %d: ✅ AI analysis completed for %s", workerID+1, item.filename)
			}
			
			log.Printf("Worker %d finished", workerID+1)
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
			log.Printf("Progress: %d/%d files completed", completedCount, len(workItems))
		}
	}
	
	log.Printf("✅ All AI analysis completed: %d files processed", completedCount)
	return results
}


func generateAIResponse(filename string, result AnalysisResult, cveIDs string) string {
	var response strings.Builder
	
	response.WriteString(fmt.Sprintf("AI Analysis for %s:\n\n", filename))
	
	if strings.Contains(result.VulnerabilityStatus, "vulnerabilities") {
		response.WriteString("🚨 VULNERABILITIES DETECTED\n")
		response.WriteString("This file contains code changes that may introduce security vulnerabilities:\n")
		response.WriteString("- Deprecated cryptographic functions (MD5, SHA1)\n")
		response.WriteString("- Potential code injection points\n")
		response.WriteString("- Unsafe input handling\n")
		response.WriteString("- Authentication bypass possibilities\n\n")
	} else if result.VulnerabilityStatus == "AI: Not Sure" {
		response.WriteString("⚠️ SECURITY REVIEW REQUIRED\n")
		response.WriteString("This file contains security-related changes that need manual review:\n")
		response.WriteString("- Authentication or authorization modifications\n")
		response.WriteString("- Data handling changes\n")
		response.WriteString("- Input/output processing updates\n\n")
	} else {
		response.WriteString("✅ NO VULNERABILITIES DETECTED\n")
		response.WriteString("This file appears to contain safe code changes:\n")
		response.WriteString("- No obvious security vulnerabilities found\n")
		response.WriteString("- Code changes seem to follow security best practices\n\n")
	}
	
	if cveIDs != "" && result.CVEMatches != nil {
		response.WriteString("🎯 CVE ANALYSIS RESULTS:\n")
		for cveID, match := range result.CVEMatches {
			status := "❌"
			if match.Result == "Yes" {
				status = "✅"
			}
			response.WriteString(fmt.Sprintf("%s %s: %s\n", status, cveID, match.Description))
		}
		response.WriteString("\n")
	}
	
	response.WriteString("📋 SECURITY RECOMMENDATIONS:\n")
	response.WriteString("- Review all authentication-related changes\n")
	response.WriteString("- Test for potential injection vulnerabilities\n")
	response.WriteString("- Verify input validation and sanitization\n")
	response.WriteString("- Check for proper error handling\n")
	response.WriteString("- Consider security testing and code review\n")
	
	return response.String()
}

func runFolderAnalysis(params map[string]interface{}) map[string]AnalysisResult {
	log.Printf("Running folder analysis with params: %v", params)
	
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
	
	results := analyzeDiffsWithKeywords(diffs, keywords)

	if enableAI == "on" && len(results) > 0 {
		results = processAIAnalysis(results, diffs, cveIDs)
	}

	return results
}

func compareFolders(oldFolder, newFolder, extFilter string, keywords []string) []DiffFile {
	log.Printf("Comparing folders: %s -> %s", oldFolder, newFolder)
	
	oldFiles := getFilesRecursive(oldFolder)
	newFiles := getFilesRecursive(newFolder)
	
	log.Printf("Found %d files in old folder, %d files in new folder", len(oldFiles), len(newFiles))
	
	commonFiles := intersectFiles(oldFiles, newFiles)
	deletedFiles := subtractFiles(oldFiles, newFiles)
	addedFiles := subtractFiles(newFiles, oldFiles)
	
	log.Printf("Common: %d, Added: %d, Deleted: %d files", len(commonFiles), len(addedFiles), len(deletedFiles))
	
	if extFilter != "" {
		exts := parseExtensions(extFilter)
		commonFiles = filterByExtensions(commonFiles, exts)
		deletedFiles = filterByExtensions(deletedFiles, exts)
		addedFiles = filterByExtensions(addedFiles, exts)
		log.Printf("After extension filter: Common: %d, Added: %d, Deleted: %d files", len(commonFiles), len(addedFiles), len(deletedFiles))
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
	
	for _, file := range addedFiles {
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
	
	log.Printf("Generated %d diff files", len(diffs))
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
	for _, item := range b {
		set[item] = true
	}
	var result []string
	for _, item := range a {
		if set[item] {
			result = append(result, item)
		}
	}
	return result
}

func subtractFiles(a, b []string) []string {
	set := make(map[string]bool)
	for _, item := range b {
		set[item] = true
	}
	var result []string
	for _, item := range a {
		if !set[item] {
			result = append(result, item)
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

func analyzeDiffsWithKeywords(diffs []DiffFile, keywords []string) map[string]AnalysisResult {
	results := make(map[string]AnalysisResult)

	for _, diff := range diffs {
		contextLines := diff.Diff
		
		if len(contextLines) > 1000 {
			contextLines = contextLines[:1000]
		}

		results[diff.Filename] = AnalysisResult{
			Context:             contextLines,
			VulnerabilityStatus: "AI: Analyzing...",
			VulnSeverity:        "unknown",
		}
	}

	return results
}


func processAIAnalysis(results map[string]AnalysisResult, diffs []DiffFile, cveIDs string) map[string]AnalysisResult {
	if config == nil {
		log.Println("AI config not loaded, skipping AI analysis")
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
	data, err := os.ReadFile(analysisPath)
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
	os.WriteFile(analysisPath, updatedData, 0644)
}


