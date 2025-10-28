package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0"
)

func validateInput(input interface{}, maxLength int) string {
	str, ok := input.(string)
	if !ok || str == "" {
		return ""
	}

	re := regexp.MustCompile(`[\x00-\x1f\x7f-\x9f]`)
	clean := re.ReplaceAllString(str, "")

	if len(clean) > maxLength {
		clean = clean[:maxLength]
	}

	return strings.TrimSpace(clean)
}

func validatePrompt(input string, maxLength int) string {
	if input == "" {
		return ""
	}

	re := regexp.MustCompile(`[\x00\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]`)
	clean := re.ReplaceAllString(input, "")

	if len(clean) > maxLength {
		clean = clean[:maxLength]
	}

	return strings.TrimSpace(clean)
}

func validateURL(url string) bool {
	if url == "" {
		return false
	}

	return strings.HasPrefix(url, "https://github.com/") || strings.HasPrefix(url, "http://github.com/")
}

func validateVersion(version string) bool {
	if version == "" {
		return false
	}
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, version)
	return matched && len(version) <= 50
}

func loadProducts() map[string]Product {
	data, err := os.ReadFile(filepath.Join("products", "products.json"))
	if err != nil {
		return make(map[string]Product)
	}

	var products map[string]Product
	if err := json.Unmarshal(data, &products); err != nil {
		return make(map[string]Product)
	}

	return products
}

func saveProducts(products map[string]Product) error {
	data, err := json.MarshalIndent(products, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join("products", "products.json"), data, 0644)
}

func loadLibrary() []LibraryRepo {
	data, err := os.ReadFile(filepath.Join("products", "library.json"))
	if err != nil {
		return []LibraryRepo{}
	}

	var library []LibraryRepo
	if err := json.Unmarshal(data, &library); err != nil {
		return []LibraryRepo{}
	}

	return library
}

func saveLibrary(library []LibraryRepo) error {
	data, err := json.MarshalIndent(library, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join("products", "library.json"), data, 0644)
}

func addLibraryRepo(name, repoURL, aiService, cpe string) error {
	library := loadLibrary()

	for _, repo := range library {
		if repo.Name == name {
			return fmt.Errorf("repository already exists")
		}
	}

	newRepo := LibraryRepo{
		ID:        uuid.New().String(),
		Name:      name,
		RepoURL:   repoURL,
		AIService: aiService,
		CPE:       cpe,
		CreatedAt: time.Now(),
		AutoScan:  true,
	}

	library = append(library, newRepo)
	return saveLibrary(library)
}

func removeLibraryRepo(repoID string) error {
	library := loadLibrary()
	
	newLibrary := []LibraryRepo{}
	for _, repo := range library {
		if repo.ID != repoID {
			newLibrary = append(newLibrary, repo)
		}
	}

	return saveLibrary(newLibrary)
}

func toggleLibraryAutoScan(repoID string) error {
	library := loadLibrary()
	
	for i, repo := range library {
		if repo.ID == repoID {
			library[i].AutoScan = !repo.AutoScan
			return saveLibrary(library)
		}
	}

	return fmt.Errorf("repository not found")
}

func getGitHubVersions(repoURL string) []string {
	if !validateURL(repoURL) {
		return []string{}
	}

	url := fmt.Sprintf("%s/refs?tag_name=&experimental=1", repoURL)
	
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return []string{}
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	
	log.Printf("DEBUG: Fetching versions from: %s", url)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching versions from GitHub: %v", err)
		return []string{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("DEBUG: GitHub returned status: %d", resp.StatusCode)
		return []string{}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return []string{}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Printf("Error parsing JSON response: %v", err)
		return []string{}
	}

	versions := []string{}
	if refs, exists := data["refs"]; exists {
		if refsList, ok := refs.([]interface{}); ok {
			for _, ref := range refsList {
				if version, ok := ref.(string); ok {
					version = strings.TrimSpace(version)
					if validateVersion(version) {
						versions = append(versions, version)
					}
				}
			}
		}
	}

	uniqueVersions := []string{}
	seen := make(map[string]bool)
	for _, version := range versions {
		if !seen[version] {
			seen[version] = true
			uniqueVersions = append(uniqueVersions, version)
		}
	}

	sort.Slice(uniqueVersions, func(i, j int) bool {
		return compareVersions(uniqueVersions[i], uniqueVersions[j]) > 0
	})

	log.Printf("DEBUG: Fetched %d versions from GitHub web interface", len(uniqueVersions))
	return uniqueVersions
}

func getGitHubVersionsByDate(repoURL string) []string {
	if !validateURL(repoURL) {
		return []string{}
	}

	url := fmt.Sprintf("%s/refs?tag_name=&experimental=1", repoURL)
	
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return []string{}
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	
	log.Printf("DEBUG: Fetching tags from: %s", url)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching tags from GitHub: %v", err)
		return []string{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("DEBUG: GitHub returned status: %d", resp.StatusCode)
		return []string{}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return []string{}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Printf("Error parsing JSON response: %v", err)
		return []string{}
	}

	
	tags := []string{}
	if refs, exists := data["refs"]; exists {
		if refsList, ok := refs.([]interface{}); ok {
			for i, ref := range refsList {
				if i >= 20 { 
					break
				}
				if version, ok := ref.(string); ok {
					version = strings.TrimSpace(version)
					if validateVersion(version) {
						tags = append(tags, version)
					}
				}
			}
		}
	}

	if len(tags) == 0 {
		log.Printf("DEBUG: No tags found for repository")
		return []string{}
	}

	log.Printf("DEBUG: Found %d tags, checking release dates", len(tags))

	
	type TagWithDate struct {
		Tag  string
		Date time.Time
	}

	var tagsWithDates []TagWithDate
	for _, tag := range tags {
		releaseURL := fmt.Sprintf("%s/releases/tag/%s", repoURL, tag)
		
		req, err := http.NewRequest("GET", releaseURL, nil)
		if err != nil {
			log.Printf("Error creating request for tag %s: %v", tag, err)
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
		
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error fetching release page for tag %s: %v", tag, err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			
			if err != nil {
				log.Printf("Error reading release page for tag %s: %v", tag, err)
				continue
			}

			
			datetime := extractDatetimeFromHTML(string(body))
			if !datetime.IsZero() {
				tagsWithDates = append(tagsWithDates, TagWithDate{Tag: tag, Date: datetime})
				log.Printf("DEBUG: Tag %s has release date %s", tag, datetime.Format(time.RFC3339))
			} else {
				log.Printf("DEBUG: Could not extract datetime for tag %s", tag)
			}
		} else {
			log.Printf("DEBUG: Release page for tag %s returned status %d", tag, resp.StatusCode)
			resp.Body.Close()
		}
	}

	
	sort.Slice(tagsWithDates, func(i, j int) bool {
		return tagsWithDates[i].Date.After(tagsWithDates[j].Date)
	})

	
	result := make([]string, len(tagsWithDates))
	for i, tagWithDate := range tagsWithDates {
		result[i] = tagWithDate.Tag
	}

	log.Printf("DEBUG: Sorted %d tags by release date", len(result))
	return result
}


func extractDatetimeFromHTML(html string) time.Time {
	
	re := regexp.MustCompile(`<relative-time[^>]*datetime="([^"]+)"`)
	matches := re.FindStringSubmatch(html)
	
	if len(matches) < 2 {
		return time.Time{}
	}

	datetimeStr := matches[1]
	
	
	formats := []string{
		"2006-01-02T15:04:05Z07:00",     
		"2006-01-02 15:04:05 UTC",       
		"2006-01-02T15:04:05Z",          
		"2006-01-02 15:04:05",           
	}
	
	for _, format := range formats {
		datetime, err := time.Parse(format, datetimeStr)
		if err == nil {
			return datetime
		}
	}
	
	log.Printf("Error parsing datetime %s: tried all supported formats", datetimeStr)
	return time.Time{}
}

func loadAllAnalyses() []Analysis {
	analyses := []Analysis{}

	files, err := os.ReadDir("saved_analyses")
	if err != nil {
		return analyses
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			analysisID := strings.TrimSuffix(file.Name(), ".json")
			if !isValidUUID(analysisID) {
				continue
			}

			data, err := os.ReadFile(filepath.Join("saved_analyses", file.Name()))
			if err != nil {
				continue
			}

			var analysis Analysis
			if err := json.Unmarshal(data, &analysis); err != nil {
				continue
			}

			analysis.ID = analysisID
			analyses = append(analyses, analysis)
		}
	}

	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].Meta.CreatedAt.After(analyses[j].Meta.CreatedAt)
	})

	return analyses
}


func filterAnalysisResults(results map[string]AnalysisResult, filterType, searchTerm string) map[string]AnalysisResult {
	filtered := make(map[string]AnalysisResult)

	for filename, result := range results {
		include := true
		switch filterType {
		case "cve":
			include = false
			if result.CVEMatches != nil {
				for _, cveData := range result.CVEMatches {
					if strings.EqualFold(cveData.Result, "Yes") {
						include = true
						break
					}
				}
			}
		case "vuln":
			status := strings.ToLower(result.VulnerabilityStatus)
			include = strings.Contains(status, "vulnerabilities") && !strings.Contains(status, "no vulnerabilities")
		}

		if !include {
			continue
		}

		if searchTerm != "" {
			aiResponse := strings.ToLower(result.AIResponse)
			filenameLower := strings.ToLower(filename)
			vulnStatus := strings.ToLower(result.VulnerabilityStatus)

			matches := strings.Contains(aiResponse, searchTerm) ||
				strings.Contains(filenameLower, searchTerm) ||
				strings.Contains(vulnStatus, searchTerm)

			if !matches && result.CVEMatches != nil {
				for cveID, cveData := range result.CVEMatches {
					cveIDLower := strings.ToLower(cveID)
					descLower := strings.ToLower(cveData.Description)
					if strings.Contains(cveIDLower, searchTerm) || strings.Contains(descLower, searchTerm) {
						matches = true
						break
					}
				}
			}

			if !matches {
				continue
			}
		}

		filtered[filename] = result
	}

	return filtered
}

func createNewAnalysisRecord(params map[string]interface{}, source string, aiEnabled bool) string {
	analysisID := uuid.New().String()

	var aiService, aiModel string
	if aiEnabled && config != nil {
		aiService = config.Service
		if svcConfig, ok := config.GetServiceConfig(aiService); ok {
			if model, ok := svcConfig["model"].(string); ok {
				aiModel = model
			}
		}
	}

	analysis := Analysis{
		Meta: AnalysisMeta{
			CreatedAt: time.Now(),
			Source:    source,
			AIEnabled: aiEnabled,
			AIService: aiService,
			AIModel:   aiModel,
			Status:    "running",
			Params:    params,
		},
		Results: make(map[string]AnalysisResult),
	}

	analysisPath := filepath.Join("saved_analyses", analysisID+".json")
	data, _ := json.MarshalIndent(analysis, "", "  ")
	os.WriteFile(analysisPath, data, 0644)

	return analysisID
}

func countVulnerabilities(results map[string]AnalysisResult) int {
	count := 0
	for _, result := range results {
		if strings.HasPrefix(result.VulnerabilityStatus, "AI: ") {
			vulnText := strings.TrimPrefix(result.VulnerabilityStatus, "AI: ")
			if !strings.HasPrefix(vulnText, "Not sure") && !strings.HasPrefix(vulnText, "No vulnerabilities") {
				parts := strings.Split(vulnText, " ")
				if len(parts) > 0 {
					var num int
					fmt.Sscanf(parts[0], "%d", &num)
					count += num
				}
			}
		}
	}
	return count
}


func splitVersionString(version string) []string {
	
	normalized := strings.ReplaceAll(version, "_", ".")
	return strings.Split(normalized, ".")
}

func compareVersions(v1, v2 string) int {
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")
	
	
	parts1 := splitVersionString(v1)
	parts2 := splitVersionString(v2)
	
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	
	for len(parts1) < maxLen {
		parts1 = append(parts1, "0")
	}
	for len(parts2) < maxLen {
		parts2 = append(parts2, "0")
	}
	
	for i := 0; i < maxLen; i++ {
		num1, err1 := parseVersionPart(parts1[i])
		num2, err2 := parseVersionPart(parts2[i])
		
		if err1 == nil && err2 == nil {
			if num1 > num2 {
				return 1
			} else if num1 < num2 {
				return -1
			}
		} else {
			if parts1[i] > parts2[i] {
				return 1
			} else if parts1[i] < parts2[i] {
				return -1
			}
		}
	}
	
	return 0
}

func parseVersionPart(part string) (int, error) {
	cleanPart := part
	for i, char := range part {
		if char < '0' || char > '9' {
			cleanPart = part[:i]
			break
		}
	}
	
	if cleanPart == "" {
		return 0, fmt.Errorf("not a number")
	}
	
	return strconv.Atoi(cleanPart)
}

func fetchCVEsFromNVD(cpeName string) ([]CVE, error) {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s", cpeName)
	log.Printf("🔗 NVD API request: %s", url)
	
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("User-Agent", "PatchLeaks/1.0")
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVEs: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("❌ NVD API returned status %d for CPE: %s", resp.StatusCode, cpeName)
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	log.Printf("📦 NVD response size: %d bytes", len(body))

	var nvdResponse NVDResponse
	if err := json.Unmarshal(body, &nvdResponse); err != nil {
		log.Printf("❌ Failed to parse NVD response: %v", err)
		log.Printf("Response preview: %s", string(body[:min(500, len(body))]))
		return nil, fmt.Errorf("failed to parse NVD response: %v", err)
	}

	log.Printf("📊 NVD reports %d total results, %d in this response", nvdResponse.TotalResults, len(nvdResponse.Vulnerabilities))

	var cves []CVE
	for _, vuln := range nvdResponse.Vulnerabilities {
		cve := vuln.CVE
		log.Printf("  ├─ %s: %s", cve.ID, cve.Description[:min(80, len(cve.Description))])
		cves = append(cves, cve)
	}

	log.Printf("✅ Parsed %d CVEs from NVD response", len(cves))
	return cves, nil
}

func getCVEsForVersion(cpe, version string) ([]CVE, error) {
	cpeVersion := strings.Replace(version, "-", ":", -1)
	
	cpeName := fmt.Sprintf("%s:%s", cpe, cpeVersion)
	log.Printf("🔍 CPE query: %s (original version: %s)", cpeName, version)
	return fetchCVEsFromNVD(cpeName)
}

func getNextIncrementalVersion(currentVersion string, allVersions []string) string {
	parts := strings.SplitN(currentVersion, "-", 2)
	if len(parts) != 2 {
		return findNextVersion(currentVersion, allVersions)
	}
	
	baseVersion := parts[0]
	
	currentIdx := -1
	for i, v := range allVersions {
		if v == currentVersion {
			currentIdx = i
			break
		}
	}
	
	if currentIdx == -1 {
		return findNextVersion(currentVersion, allVersions)
	}
	
	for i := 0; i < currentIdx; i++ {
		v := allVersions[i]
		if strings.HasPrefix(v, baseVersion+"-") {
			log.Printf("🔄 Found incremental version: %s → %s", currentVersion, v)
			return v
		}
	}
	
	nextVer := findNextVersion(currentVersion, allVersions)
	log.Printf("📈 No incremental version found, jumping to: %s → %s", currentVersion, nextVer)
	return nextVer
}

func findNextVersion(currentVersion string, allVersions []string) string {
	currentIdx := -1
	for i, v := range allVersions {
		if v == currentVersion {
			currentIdx = i
			break
		}
	}
	
	if currentIdx >= 0 && currentIdx > 0 {
		return allVersions[currentIdx-1]
	}
	
	if len(allVersions) > 0 {
		return allVersions[0]
	}
	
	return currentVersion
}

func updateAnalysisParams(analysisID string, params map[string]interface{}) error {
	analysisPath := filepath.Join("saved_analyses", analysisID+".json")
	
	data, err := os.ReadFile(analysisPath)
	if err != nil {
		return fmt.Errorf("failed to read analysis file: %w", err)
	}
	
	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		return fmt.Errorf("failed to unmarshal analysis: %w", err)
	}
	
	analysis.Meta.Params = params
	
	updatedData, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal analysis: %w", err)
	}
	
	if err := os.WriteFile(analysisPath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write analysis file: %w", err)
	}
	
	return nil
}

func runCVEBasedAnalysis(analysisID string, params map[string]interface{}) map[string]AnalysisResult {
	log.Printf("🔍 Running CVE-based analysis with params: %v", params)
	
	repoName, _ := params["repo_name"].(string)
	repoURL, _ := params["repo_url"].(string)
	oldVersion, _ := params["old_version"].(string)
	newVersion, _ := params["new_version"].(string)
	cpe, _ := params["cpe"].(string)
	enableAIStr, _ := params["enable_ai"].(string)
	enableAI := enableAIStr == "on"
	extension, _ := params["extension"].(string)
	specialKeywords, _ := params["special_keywords"].(string)
	
	if repoURL == "" || oldVersion == "" || newVersion == "" || cpe == "" {
		log.Printf("Missing required parameters for CVE-based analysis")
		return make(map[string]AnalysisResult)
	}
	
	log.Printf("🔍 Analyzing %s: %s → %s using CVE data (CPE: %s)", repoName, oldVersion, newVersion, cpe)
	
	log.Printf("📡 Fetching CVEs for version %s using CPE: %s", oldVersion, cpe)
	oldCVEs, err := getCVEsForVersion(cpe, oldVersion)
	if err != nil {
		log.Printf("❌ Failed to fetch CVEs for old version: %v", err)
		log.Printf("💡 This might be due to:")
		log.Printf("   - Invalid CPE format")
		log.Printf("   - Version not found in NVD database")
		log.Printf("   - NVD API connectivity issues")
		log.Printf("   - Date parsing issues (now fixed)")
		return make(map[string]AnalysisResult)
	}
	
	log.Printf("✅ Found %d CVEs for old version %s", len(oldCVEs), oldVersion)
	if len(oldCVEs) == 0 {
		log.Printf("⚠️  No CVEs found for version %s - analysis will proceed without CVE matching", oldVersion)
	} else {
		cveIDs := make([]string, 0, len(oldCVEs))
		for _, cve := range oldCVEs {
			cveIDs = append(cveIDs, cve.ID)
		}
		params["cve_ids"] = strings.Join(cveIDs, ", ")
		log.Printf("📋 CVE IDs stored in params: %s", params["cve_ids"])
		
		if err := updateAnalysisParams(analysisID, params); err != nil {
			log.Printf("⚠️  Failed to update analysis params with CVE IDs: %v", err)
		} else {
			log.Printf("✅ Updated analysis file with CVE IDs for immediate UI display")
		}
	}
	
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
	
	diffs := compareDirectories(oldPath, newPath, extension)
	log.Printf("Found %d file differences", len(diffs))
	
	results := analyzeDiffsWithCVEs(diffs, specialKeywords, oldCVEs)
	
	if enableAI && len(results) > 0 {
		results = runAIAnalysisOnResults(results, "", *aiThreads)
	}
	
	log.Printf("🎯 CVE-based analysis complete: %d files with potential issues", len(results))
	return results
}

func analyzeDiffsWithCVEs(diffs []DiffFile, keywords string, cves []CVE) map[string]AnalysisResult {
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
		
		if len(cves) > 0 {
			result.CVEMatches = make(map[string]CVEMatch)
			for _, cve := range cves {
				result.CVEMatches[cve.ID] = CVEMatch{
					Description: cve.Description,
					Result:      "Pending AI analysis",
				}
			}
		}
		
		results[diff.Filename] = result
	}
	
	return results
}


