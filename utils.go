package main
import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)
const (
	UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0"
)
const recentTagLimit = 15
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
	data, err := TrackedReadFile(filepath.Join("products", "products.json"))
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
	return TrackedWriteFile(filepath.Join("products", "products.json"), data, 0644)
}
func loadLibrary() []LibraryRepo {
	data, err := TrackedReadFile(filepath.Join("products", "library.json"))
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
	return TrackedWriteFile(filepath.Join("products", "library.json"), data, 0644)
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
		return []string{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return []string{}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []string{}
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
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
		return []string{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return []string{}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []string{}
	}
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return []string{}
	}
	tags := []string{}
	if refs, exists := data["refs"]; exists {
		if refsList, ok := refs.([]interface{}); ok {
			for i, ref := range refsList {
				if i >= recentTagLimit {
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
		return []string{}
	}
	type TagWithDate struct {
		Tag  string
		Date time.Time
	}
	var tagsWithDates []TagWithDate
	type job struct{ tag string }
	type tagDateResult struct {
		tag  string
		date time.Time
	}
	jobs := make(chan job, len(tags))
	results := make(chan tagDateResult, len(tags))
	workerCount := 6
	if workerCount > len(tags) {
		workerCount = len(tags)
	}
	var wg sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				releaseURL := fmt.Sprintf("%s/releases/tag/%s", repoURL, j.tag)
				req, err := http.NewRequest("GET", releaseURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				if resp.StatusCode == http.StatusOK {
					body, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						continue
					}
					datetime := extractDatetimeFromHTML(string(body))
					if !datetime.IsZero() {
						results <- tagDateResult{tag: j.tag, date: datetime}
					}
				} else {
					resp.Body.Close()
				}
			}
		}()
	}
	for _, t := range tags {
		jobs <- job{tag: t}
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()
	for r := range results {
		tagsWithDates = append(tagsWithDates, TagWithDate{Tag: r.tag, Date: r.date})
	}
	sort.Slice(tagsWithDates, func(i, j int) bool {
		return tagsWithDates[i].Date.After(tagsWithDates[j].Date)
	})
	result := make([]string, len(tagsWithDates))
	for i, tagWithDate := range tagsWithDates {
		result[i] = tagWithDate.Tag
	}
	return result
}
func extractDatetimeFromHTML(html string) time.Time {
	tagRe := regexp.MustCompile(`<relative-time[^>]*>`)
	classRe := regexp.MustCompile(`\bclass="([^"]+)"`)
	thresholdRe := regexp.MustCompile(`\bthreshold\s*=`)
	datetimeRe := regexp.MustCompile(`\bdatetime="([^"]+)"`)
	tags := tagRe.FindAllString(html, -1)
	for _, tag := range tags {
		if thresholdRe.MatchString(tag) {
			continue
		}
		classMatch := classRe.FindStringSubmatch(tag)
		if len(classMatch) < 2 || classMatch[1] != "no-wrap" {
			continue
		}
		dtMatch := datetimeRe.FindStringSubmatch(tag)
		if len(dtMatch) < 2 {
			continue
		}
		datetimeStr := dtMatch[1]
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
	}
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
			data, err := TrackedReadFile(filepath.Join("saved_analyses", file.Name()))
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
	TrackedWriteFile(analysisPath, data, 0644)
	InvalidateDashboardCache()
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
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", "PatchLeaks/1.0")
	if config != nil && config.NVD != nil {
		if apiKey, ok := config.NVD["api_key"].(string); ok && apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVEs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	var nvdResponse NVDResponse
	if err := json.Unmarshal(body, &nvdResponse); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %v", err)
	}
	var cves []CVE
	for _, vuln := range nvdResponse.Vulnerabilities {
		cves = append(cves, vuln.CVE)
	}
	return cves, nil
}
func getCVEsForVersion(cpe, version string) ([]CVE, error) {
	cpeVersion := strings.Replace(version, "-", ":", -1)
	cpeName := fmt.Sprintf("%s:%s", cpe, cpeVersion)
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
			return v
		}
	}
	nextVer := findNextVersion(currentVersion, allVersions)
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
	data, err := TrackedReadFile(analysisPath)
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
	if err := TrackedWriteFile(analysisPath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write analysis file: %w", err)
	}
	return nil
}
func runCVEBasedAnalysis(analysisID string, params map[string]interface{}) map[string]AnalysisResult {
	_, _ = params["repo_name"].(string)
	repoURL, _ := params["repo_url"].(string)
	oldVersion, _ := params["old_version"].(string)
	newVersion, _ := params["new_version"].(string)
	cpe, _ := params["cpe"].(string)
	enableAIStr, _ := params["enable_ai"].(string)
	enableAI := enableAIStr == "on"
	extension, _ := params["extension"].(string)
	specialKeywords, _ := params["special_keywords"].(string)
	if repoURL == "" || oldVersion == "" || newVersion == "" || cpe == "" {
		return make(map[string]AnalysisResult)
	}
	oldCVEs, err := getCVEsForVersion(cpe, oldVersion)
	if err != nil {
		return make(map[string]AnalysisResult)
	}
	if len(oldCVEs) == 0 {
	} else {
		cveIDs := make([]string, 0, len(oldCVEs))
		for _, cve := range oldCVEs {
			cveIDs = append(cveIDs, cve.ID)
		}
		params["cve_ids"] = strings.Join(cveIDs, ", ")
		if err := updateAnalysisParams(analysisID, params); err != nil {
		}
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
	results := analyzeDiffsWithCVEs(diffs, specialKeywords, oldCVEs, enableAI)
	if enableAI && len(results) > 0 {
		cveIDsStr, _ := params["cve_ids"].(string)
		results = runAIAnalysisOnResults(results, cveIDsStr, *aiThreads, newPath)
	}
	return results
}
func analyzeDiffsWithCVEs(diffs []DiffFile, keywords string, cves []CVE, enableAI bool) map[string]AnalysisResult {
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
