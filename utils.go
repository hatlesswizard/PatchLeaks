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

// validateInput validates and sanitizes input strings
func validateInput(input interface{}, maxLength int) string {
	str, ok := input.(string)
	if !ok || str == "" {
		return ""
	}

	// Remove control characters
	re := regexp.MustCompile(`[\x00-\x1f\x7f-\x9f]`)
	clean := re.ReplaceAllString(str, "")

	// Truncate if too long
	if len(clean) > maxLength {
		clean = clean[:maxLength]
	}

	return strings.TrimSpace(clean)
}

// validatePrompt validates prompt strings
func validatePrompt(input string, maxLength int) string {
	if input == "" {
		return ""
	}

	// Remove problematic control characters but keep newlines and tabs
	re := regexp.MustCompile(`[\x00\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]`)
	clean := re.ReplaceAllString(input, "")

	if len(clean) > maxLength {
		clean = clean[:maxLength]
	}

	return strings.TrimSpace(clean)
}

// validateURL validates a GitHub URL
func validateURL(url string) bool {
	if url == "" {
		return false
	}

	return strings.HasPrefix(url, "https://github.com/") || strings.HasPrefix(url, "http://github.com/")
}

// validateVersion validates a version string
func validateVersion(version string) bool {
	if version == "" {
		return false
	}
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9._-]+$`, version)
	return matched && len(version) <= 50
}

// loadProducts loads products from file
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

// saveProducts saves products to file
func saveProducts(products map[string]Product) error {
	data, err := json.MarshalIndent(products, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join("products", "products.json"), data, 0644)
}

// loadLibrary loads library repositories from file
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

// saveLibrary saves library repositories to file
func saveLibrary(library []LibraryRepo) error {
	data, err := json.MarshalIndent(library, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join("products", "library.json"), data, 0644)
}

// addLibraryRepo adds a repository to the library
func addLibraryRepo(name, repoURL, aiService, cpe string) error {
	library := loadLibrary()

	// Check if already exists
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

// removeLibraryRepo removes a repository from the library
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

// toggleLibraryAutoScan toggles auto-scan for a library repository
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

// getGitHubVersions fetches versions/tags from a GitHub repository using web interface
func getGitHubVersions(repoURL string) []string {
	if !validateURL(repoURL) {
		return []string{}
	}

	// Use GitHub web interface instead of API to avoid rate limits
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

	// Parse JSON response
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Printf("Error parsing JSON response: %v", err)
		return []string{}
	}

	// Extract versions from refs array
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

	// Remove duplicates while preserving order
	uniqueVersions := []string{}
	seen := make(map[string]bool)
	for _, version := range versions {
		if !seen[version] {
			seen[version] = true
			uniqueVersions = append(uniqueVersions, version)
		}
	}

	// Sort versions using semantic versioning
	sort.Slice(uniqueVersions, func(i, j int) bool {
		return compareVersions(uniqueVersions[i], uniqueVersions[j]) > 0
	})

	log.Printf("DEBUG: Fetched %d versions from GitHub web interface", len(uniqueVersions))
	return uniqueVersions
}

// loadAllAnalyses loads all saved analyses
func loadAllAnalyses() []Analysis {
	analyses := []Analysis{}

	files, err := os.ReadDir("saved_analyses")
	if err != nil {
		return analyses
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") && !strings.HasPrefix(file.Name(), "benchmark_") {
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

	// Sort by creation date (newest first)
	sort.Slice(analyses, func(i, j int) bool {
		return analyses[i].Meta.CreatedAt.After(analyses[j].Meta.CreatedAt)
	})

	return analyses
}

// loadBenchmarkResults loads all benchmark results
func loadBenchmarkResults() []BenchmarkResult {
	results := []BenchmarkResult{}

	files, err := os.ReadDir("saved_analyses")
	if err != nil {
		return results
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "benchmark_") && strings.HasSuffix(file.Name(), ".json") {
			benchmarkID := strings.TrimSuffix(strings.TrimPrefix(file.Name(), "benchmark_"), ".json")
			if !isValidUUID(benchmarkID) {
				continue
			}

			data, err := os.ReadFile(filepath.Join("saved_analyses", file.Name()))
			if err != nil {
				continue
			}

			var result BenchmarkResult
			if err := json.Unmarshal(data, &result); err != nil {
				continue
			}

			result.BenchmarkID = benchmarkID
			results = append(results, result)
		}
	}

	// Sort by creation date (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})

	return results
}

// filterAnalysisResults filters analysis results based on criteria
func filterAnalysisResults(results map[string]AnalysisResult, filterType, searchTerm string) map[string]AnalysisResult {
	filtered := make(map[string]AnalysisResult)

	for filename, result := range results {
		// Apply filter
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

		// Apply search
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

// createNewAnalysisRecord creates a new analysis record
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

// countVulnerabilities counts vulnerabilities in analysis results
func countVulnerabilities(results map[string]AnalysisResult) int {
	count := 0
	for _, result := range results {
		if strings.HasPrefix(result.VulnerabilityStatus, "AI: ") {
			vulnText := strings.TrimPrefix(result.VulnerabilityStatus, "AI: ")
			if !strings.HasPrefix(vulnText, "Not sure") && !strings.HasPrefix(vulnText, "No vulnerabilities") {
				// Try to extract number
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

// compareVersions compares two version strings using semantic versioning
// Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if v1 == v2
func compareVersions(v1, v2 string) int {
	// Remove 'v' prefix if present
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")
	
	// Split versions into parts
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	
	// Pad shorter version with zeros
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	
	// Pad both arrays to same length
	for len(parts1) < maxLen {
		parts1 = append(parts1, "0")
	}
	for len(parts2) < maxLen {
		parts2 = append(parts2, "0")
	}
	
	// Compare each part
	for i := 0; i < maxLen; i++ {
		num1, err1 := parseVersionPart(parts1[i])
		num2, err2 := parseVersionPart(parts2[i])
		
		// If both are numbers, compare numerically
		if err1 == nil && err2 == nil {
			if num1 > num2 {
				return 1
			} else if num1 < num2 {
				return -1
			}
		} else {
			// If one or both are not numbers, compare as strings
			if parts1[i] > parts2[i] {
				return 1
			} else if parts1[i] < parts2[i] {
				return -1
			}
		}
	}
	
	return 0
}

// parseVersionPart parses a version part (e.g., "11", "1", "beta") 
// Returns the numeric value if it's a number, or an error if it's not
func parseVersionPart(part string) (int, error) {
	// Remove any non-numeric suffix (e.g., "11-beta" -> "11")
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

// fetchCVEsFromNVD fetches CVEs for a specific CPE and version from NVD API
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

// getCVEsForVersion gets CVEs for a specific version using CPE
func getCVEsForVersion(cpe, version string) ([]CVE, error) {
	// NVD CPE format uses colons, not hyphens for version parts
	// Example: "2.4.9-alpha2" becomes "2.4.9:alpha2" in CPE
	cpeVersion := strings.Replace(version, "-", ":", -1)
	
	// Construct CPE name with version
	cpeName := fmt.Sprintf("%s:%s", cpe, cpeVersion)
	log.Printf("🔍 CPE query: %s (original version: %s)", cpeName, version)
	return fetchCVEsFromNVD(cpeName)
}

// getNextIncrementalVersion finds the next incremental version (e.g., p1→p2, alpha2→alpha3)
// If no incremental version exists, returns the next available version
func getNextIncrementalVersion(currentVersion string, allVersions []string) string {
	// Extract base version and suffix
	// Examples: "2.4.8-p1" → base="2.4.8", suffix="p1"
	//           "2.4.9-alpha2" → base="2.4.9", suffix="alpha2"
	parts := strings.SplitN(currentVersion, "-", 2)
	if len(parts) != 2 {
		// No suffix, just return next available version
		return findNextVersion(currentVersion, allVersions)
	}
	
	baseVersion := parts[0]
	
	// Find current version's position in the list
	currentIdx := -1
	for i, v := range allVersions {
		if v == currentVersion {
			currentIdx = i
			break
		}
	}
	
	if currentIdx == -1 {
		// Current version not in list, just return next available
		return findNextVersion(currentVersion, allVersions)
	}
	
	// Look for incremental versions with same base that come BEFORE current (i.e., newer)
	// allVersions is sorted newest first, so we only check indices 0 to currentIdx-1
	for i := 0; i < currentIdx; i++ {
		v := allVersions[i]
		if strings.HasPrefix(v, baseVersion+"-") {
			// Found a newer incremental version with same base
			log.Printf("🔄 Found incremental version: %s → %s", currentVersion, v)
			return v
		}
	}
	
	// No newer incremental version found, return next major/minor version
	nextVer := findNextVersion(currentVersion, allVersions)
	log.Printf("📈 No incremental version found, jumping to: %s → %s", currentVersion, nextVer)
	return nextVer
}

// findNextVersion finds the next version in the list after currentVersion
func findNextVersion(currentVersion string, allVersions []string) string {
	// Find current version index
	currentIdx := -1
	for i, v := range allVersions {
		if v == currentVersion {
			currentIdx = i
			break
		}
	}
	
	// Return next version if available
	if currentIdx >= 0 && currentIdx > 0 {
		return allVersions[currentIdx-1] // versions are sorted newest first
	}
	
	// If current version not found or is latest, return first version
	if len(allVersions) > 0 {
		return allVersions[0]
	}
	
	return currentVersion
}

// updateAnalysisParams updates the params in an existing analysis file
func updateAnalysisParams(analysisID string, params map[string]interface{}) error {
	analysisPath := filepath.Join("saved_analyses", analysisID+".json")
	
	// Read existing analysis
	data, err := os.ReadFile(analysisPath)
	if err != nil {
		return fmt.Errorf("failed to read analysis file: %w", err)
	}
	
	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		return fmt.Errorf("failed to unmarshal analysis: %w", err)
	}
	
	// Update params
	analysis.Meta.Params = params
	
	// Save updated analysis
	updatedData, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal analysis: %w", err)
	}
	
	if err := os.WriteFile(analysisPath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write analysis file: %w", err)
	}
	
	return nil
}

// runCVEBasedAnalysis runs analysis using CVE data from NVD
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
	
	// Validate inputs
	if repoURL == "" || oldVersion == "" || newVersion == "" || cpe == "" {
		log.Printf("Missing required parameters for CVE-based analysis")
		return make(map[string]AnalysisResult)
	}
	
	log.Printf("🔍 Analyzing %s: %s → %s using CVE data (CPE: %s)", repoName, oldVersion, newVersion, cpe)
	
	// 1. Get CVEs for the old version
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
		// Store CVE IDs in params for UI display
		cveIDs := make([]string, 0, len(oldCVEs))
		for _, cve := range oldCVEs {
			cveIDs = append(cveIDs, cve.ID)
		}
		params["cve_ids"] = strings.Join(cveIDs, ", ")
		log.Printf("📋 CVE IDs stored in params: %s", params["cve_ids"])
		
		// Immediately update the analysis file so CVE IDs show in UI while analysis is running
		if err := updateAnalysisParams(analysisID, params); err != nil {
			log.Printf("⚠️  Failed to update analysis params with CVE IDs: %v", err)
		} else {
			log.Printf("✅ Updated analysis file with CVE IDs for immediate UI display")
		}
	}
	
	// 2. Download and extract both versions (cached)
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
	
	// 3. Compare directories and generate diffs
	diffs := compareDirectories(oldPath, newPath, extension)
	log.Printf("Found %d file differences", len(diffs))
	
	// 4. Analyze diffs for vulnerabilities using CVE data
	results := analyzeDiffsWithCVEs(diffs, specialKeywords, oldCVEs)
	
	// 5. Run AI analysis if enabled
	if enableAI && len(results) > 0 {
		results = runAIAnalysisOnResults(results, "", *aiThreads)
	}
	
	log.Printf("🎯 CVE-based analysis complete: %d files with potential issues", len(results))
	return results
}

// analyzeDiffsWithCVEs prepares diffs with CVE data for AI analysis
func analyzeDiffsWithCVEs(diffs []DiffFile, keywords string, cves []CVE) map[string]AnalysisResult {
	results := make(map[string]AnalysisResult)
	
	for _, diff := range diffs {
		if !validateFilename(diff.Filename) {
			continue
		}
		
		// Send ALL diffs to AI - no keyword filtering
		contextLines := diff.Diff
		
		// Limit context lines to prevent oversized requests
		if len(contextLines) > 1000 {
			contextLines = contextLines[:1000]
		}
		
		result := AnalysisResult{
			Context: contextLines,
		}
		
		// Set initial vulnerability status (will be updated by AI analysis)
		result.VulnerabilityStatus = "AI: Analyzing..."
		result.VulnSeverity = "unknown"
		
		// Store CVE info for AI to match against
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


