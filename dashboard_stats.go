package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)


type DashboardStats struct {
	Timestamp         time.Time           `json:"timestamp"`
	AnalysisMetrics   AnalysisMetrics     `json:"analysis_metrics"`
	VulnerabilityMets VulnerabilityMetrics `json:"vulnerability_metrics"`
	CVEMetrics        CVEMetrics          `json:"cve_metrics"`
	AIMetrics         AIMetrics           `json:"ai_metrics"`
	RepositoryMetrics RepositoryMetrics   `json:"repository_metrics"`
	FileMetrics       FileMetrics         `json:"file_metrics"`
	CacheMetrics      CacheMetricsStats   `json:"cache_metrics"`
	TrendMetrics      TrendMetrics        `json:"trend_metrics"`
	ProductMetrics    ProductMetrics      `json:"product_metrics"`
	SystemMetrics     SystemMetrics       `json:"system_metrics"`
	LanguageStats     LanguageStats       `json:"language_stats"`
}

type AnalysisMetrics struct {
	TotalCompleted  int     `json:"total_completed"`
	ActiveRunning   int     `json:"active_running"`
	TotalVulns      int     `json:"total_vulnerabilities"`
	AvgVulnsPerAnalysis float64 `json:"avg_vulnerabilities_per_analysis"`
	DetectionRate   float64 `json:"vulnerability_detection_rate"`
}

type VulnerabilityMetrics struct {
	ByProduct          map[string]int    `json:"by_product"`
	TopVulnerabilities []VulnerabilityType `json:"top_vulnerabilities"`
}

type VulnerabilityType struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type CVEMetrics struct {
	TotalMatches int     `json:"total_matches"`
	MatchRate    float64 `json:"match_rate"`
}

type AIMetrics struct {
	AvgAnalysisTimeByScale map[string]int  `json:"avg_analysis_time_by_scale"`
	ConfidenceLevels       ConfidenceLevels `json:"confidence_levels"`
	ActiveThreads          int             `json:"active_threads"`
	MaxThreads             int             `json:"max_threads"`
}

type ConfidenceLevels struct {
	Confirmed      int `json:"confirmed"`
	Uncertain      int `json:"uncertain"`
	ClearNegative  int `json:"clear_negative"`
}

type RepositoryMetrics struct {
	MonitoredLibraries   int                `json:"monitored_libraries"`
	AutoScanEnabled      int                `json:"auto_scan_enabled"`
	VersionChecks        int                `json:"version_checks_performed"`
	NewVersionsDetected  int                `json:"new_versions_detected"`
	MostActiveRepos      []RepositoryActivity `json:"most_active_repositories"`
}

type RepositoryActivity struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type FileMetrics struct {
	TotalFilesAnalyzed int `json:"total_files_analyzed"`
}

type CacheMetricsStats struct {
	SizeBytes          int64   `json:"size_bytes"`
	CachedVersions     int     `json:"cached_versions"`
	HitRate            float64 `json:"hit_rate"`
	AvgDownloadTime    float64 `json:"avg_download_time_seconds"`
	DiskSpaceSaved     int64   `json:"disk_space_saved_bytes"`
}

type TrendMetrics struct {
	AnalysesPerDay         map[string]int `json:"analyses_per_day"`
	AvgTimeByType          map[string]float64 `json:"avg_time_by_type"`
	HistoricalVulnTrends   []VulnTrendPoint `json:"historical_vuln_trends"`
}

type VulnTrendPoint struct {
	Month string `json:"month"`
	Count int    `json:"count"`
}

type ProductMetrics struct {
	TotalConfigured   int           `json:"total_configured"`
	MostAnalyzed      []ProductActivity `json:"most_analyzed"`
	AvgCoverage       float64       `json:"avg_coverage"`
}

type ProductActivity struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type SystemMetrics struct {
	MemoryMB    uint64 `json:"memory_mb"`
	Goroutines  int    `json:"goroutines"`
}

type LanguageStats struct {
	Products []LanguageStat `json:"products"`
	Library  []LanguageStat `json:"library"`
	Folder   []LanguageStat `json:"folder"`
}

type LanguageStat struct {
	Language  string `json:"language"`
	FileCount int    `json:"file_count"`
}


var (
	dashboardCache      *DashboardStats
	dashboardCacheMutex sync.RWMutex
	dashboardCacheTime  time.Time
	dashboardCacheTTL   = 5 * time.Minute
)


func GetDashboardStats() (*DashboardStats, error) {
	dashboardCacheMutex.RLock()
	if dashboardCache != nil && time.Since(dashboardCacheTime) < dashboardCacheTTL {
		defer dashboardCacheMutex.RUnlock()
		return dashboardCache, nil
	}
	dashboardCacheMutex.RUnlock()

	log.Printf("Calculating dashboard statistics...")
	stats := &DashboardStats{
		Timestamp: time.Now(),
	}

	
	analyses := loadAllAnalyses()

	
	stats.AnalysisMetrics = calculateAnalysisMetrics(analyses)
	stats.VulnerabilityMets = calculateVulnerabilityMetrics(analyses)
	stats.CVEMetrics = calculateCVEMetrics(analyses)
	stats.AIMetrics = calculateAIMetrics(analyses)
	stats.RepositoryMetrics = calculateRepositoryMetrics(analyses)
	stats.FileMetrics = calculateFileMetrics(analyses)
	stats.CacheMetrics = calculateCacheMetrics()
	stats.TrendMetrics = calculateTrendMetrics(analyses)
	stats.ProductMetrics = calculateProductMetrics(analyses)
	stats.SystemMetrics = calculateSystemMetrics()
	stats.LanguageStats = calculateLanguageStats(analyses)

	
	dashboardCacheMutex.Lock()
	dashboardCache = stats
	dashboardCacheTime = time.Now()
	dashboardCacheMutex.Unlock()

	log.Printf("Dashboard statistics calculated successfully")
	return stats, nil
}

func calculateAnalysisMetrics(analyses []Analysis) AnalysisMetrics {
	metrics := AnalysisMetrics{}
	totalVulns := 0
	vulnAnalyses := 0

	for _, analysis := range analyses {
		if analysis.Meta.Status == "completed" {
			metrics.TotalCompleted++
			vulnCount := countVulnerabilities(analysis.Results)
			if vulnCount > 0 {
				vulnAnalyses++
				totalVulns += vulnCount
			}
		} else if analysis.Meta.Status == "in_progress" || analysis.Meta.Status == "analyzing" {
			metrics.ActiveRunning++
		}
	}

	metrics.TotalVulns = totalVulns
	if metrics.TotalCompleted > 0 {
		metrics.AvgVulnsPerAnalysis = float64(totalVulns) / float64(metrics.TotalCompleted)
		metrics.DetectionRate = (float64(vulnAnalyses) / float64(metrics.TotalCompleted)) * 100
	}

	return metrics
}

func calculateVulnerabilityMetrics(analyses []Analysis) VulnerabilityMetrics {
	metrics := VulnerabilityMetrics{
		ByProduct: make(map[string]int),
	}

	vulnTypes := make(map[string]int)

	for _, analysis := range analyses {
		if analysis.Meta.Status != "completed" {
			continue
		}

		
		productName := ""
		if product, ok := analysis.Meta.Params["product"].(string); ok {
			productName = product
		} else if repoName, ok := analysis.Meta.Params["repo_name"].(string); ok {
			productName = repoName
		}

		vulnCount := countVulnerabilities(analysis.Results)
		if productName != "" && vulnCount > 0 {
			metrics.ByProduct[productName] += vulnCount
		}

		
		for _, result := range analysis.Results {
			if result.AIResponse != "" {
				types := extractVulnerabilityTypes(result.AIResponse)
				for _, vType := range types {
					vulnTypes[vType]++
				}
			}
		}
	}

	
	for vType, count := range vulnTypes {
		metrics.TopVulnerabilities = append(metrics.TopVulnerabilities, VulnerabilityType{
			Type:  vType,
			Count: count,
		})
	}

	sort.Slice(metrics.TopVulnerabilities, func(i, j int) bool {
		return metrics.TopVulnerabilities[i].Count > metrics.TopVulnerabilities[j].Count
	})

	if len(metrics.TopVulnerabilities) > 10 {
		metrics.TopVulnerabilities = metrics.TopVulnerabilities[:10]
	}

	return metrics
}

func extractVulnerabilityTypes(aiResponse string) []string {
	types := []string{}
	lowerResponse := strings.ToLower(aiResponse)

	vulnKeywords := map[string]string{
		"sql injection":           "SQL Injection",
		"xss":                     "Cross-Site Scripting (XSS)",
		"cross-site scripting":    "Cross-Site Scripting (XSS)",
		"remote code execution":   "Remote Code Execution (RCE)",
		"rce":                     "Remote Code Execution (RCE)",
		"csrf":                    "Cross-Site Request Forgery (CSRF)",
		"path traversal":          "Path Traversal",
		"directory traversal":     "Path Traversal",
		"command injection":       "Command Injection",
		"authentication bypass":   "Authentication Bypass",
		"authorization":           "Authorization Vulnerability",
		"buffer overflow":         "Buffer Overflow",
		"denial of service":       "Denial of Service (DoS)",
		"dos":                     "Denial of Service (DoS)",
		"information disclosure":  "Information Disclosure",
		"insecure deserialization": "Insecure Deserialization",
		"xxe":                     "XML External Entity (XXE)",
		"ssrf":                    "Server-Side Request Forgery (SSRF)",
	}

	found := make(map[string]bool)
	for keyword, vulnType := range vulnKeywords {
		if strings.Contains(lowerResponse, keyword) && !found[vulnType] {
			types = append(types, vulnType)
			found[vulnType] = true
		}
	}

	return types
}

func calculateCVEMetrics(analyses []Analysis) CVEMetrics {
	metrics := CVEMetrics{}
	totalChecks := 0

	for _, analysis := range analyses {
		if analysis.Meta.Status != "completed" {
			continue
		}

		for _, result := range analysis.Results {
			if result.CVEMatches != nil {
				for _, match := range result.CVEMatches {
					totalChecks++
					if match.Result == "Yes" {
						metrics.TotalMatches++
					}
				}
			}
		}
	}

	if totalChecks > 0 {
		metrics.MatchRate = (float64(metrics.TotalMatches) / float64(totalChecks)) * 100
	}

	return metrics
}

func calculateAIMetrics(analyses []Analysis) AIMetrics {
	metrics := AIMetrics{
		AvgAnalysisTimeByScale: make(map[string]int),
		MaxThreads:             *aiThreads,
	}

	
	timeBuckets := map[string][]float64{
		"10_files":   {},
		"100_files":  {},
		"1000_files": {},
	}

	confidenceStats := make(map[string]int)

	for _, analysis := range analyses {
		if analysis.Meta.Status != "completed" {
			continue
		}

		
		fileCount := len(analysis.Results)
		if analysis.Meta.FinishedAt != nil {
			duration := analysis.Meta.FinishedAt.Sub(analysis.Meta.CreatedAt).Seconds()
			
			
			if duration > 0 {
				
				if fileCount <= 50 {
					timeBuckets["10_files"] = append(timeBuckets["10_files"], duration)
				} else if fileCount <= 500 {
					timeBuckets["100_files"] = append(timeBuckets["100_files"], duration)
				} else {
					timeBuckets["1000_files"] = append(timeBuckets["1000_files"], duration)
				}
			}
		}

		
		for _, result := range analysis.Results {
			status := strings.ToLower(result.VulnerabilityStatus)
			if strings.Contains(status, "yes") || strings.Contains(status, "vulnerabilities") {
				confidenceStats["confirmed"]++
			} else if strings.Contains(status, "not sure") {
				confidenceStats["uncertain"]++
			} else if strings.Contains(status, "no") {
				confidenceStats["clear_negative"]++
			}
		}
	}

	
	for bucket, times := range timeBuckets {
		if len(times) > 0 {
			var sum float64
			for _, t := range times {
				sum += t
			}
			metrics.AvgAnalysisTimeByScale[bucket] = int(sum / float64(len(times)))
		}
	}

	metrics.ConfidenceLevels = ConfidenceLevels{
		Confirmed:     confidenceStats["confirmed"],
		Uncertain:     confidenceStats["uncertain"],
		ClearNegative: confidenceStats["clear_negative"],
	}

	
	metrics.ActiveThreads = getActiveAIThreads()

	return metrics
}

func calculateRepositoryMetrics(analyses []Analysis) RepositoryMetrics {
	metrics := RepositoryMetrics{
		MostActiveRepos: []RepositoryActivity{},
	}

	
	library := loadLibrary()
	metrics.MonitoredLibraries = len(library)
	for _, repo := range library {
		if repo.AutoScan {
			metrics.AutoScanEnabled++
		}
		if repo.LastChecked != nil {
			metrics.VersionChecks++
		}
	}

	
	repoActivity := make(map[string]int)
	for _, analysis := range analyses {
		if analysis.Meta.Status != "completed" {
			continue
		}

		
		if analysis.Meta.Source == "library" || analysis.Meta.Source == "library_auto" {
			if repoName, ok := analysis.Meta.Params["repo_name"].(string); ok {
				repoActivity[repoName]++
			} else if repoURL, ok := analysis.Meta.Params["repo_url"].(string); ok {
				repoActivity[repoURL]++
			}
		}
	}

	
	for repo, count := range repoActivity {
		metrics.MostActiveRepos = append(metrics.MostActiveRepos, RepositoryActivity{
			Name:  repo,
			Count: count,
		})
	}

	sort.Slice(metrics.MostActiveRepos, func(i, j int) bool {
		return metrics.MostActiveRepos[i].Count > metrics.MostActiveRepos[j].Count
	})

	if len(metrics.MostActiveRepos) > 10 {
		metrics.MostActiveRepos = metrics.MostActiveRepos[:10]
	}

	
	metrics.NewVersionsDetected = getNewVersionsDetected()

	return metrics
}

func calculateFileMetrics(analyses []Analysis) FileMetrics {
	metrics := FileMetrics{}

	for _, analysis := range analyses {
		if analysis.Meta.Status == "completed" {
			metrics.TotalFilesAnalyzed += len(analysis.Results)
		}
	}

	return metrics
}

func calculateCacheMetrics() CacheMetricsStats {
	metrics := CacheMetricsStats{}

	count, size, err := getCacheStats()
	if err == nil {
		metrics.CachedVersions = count
		metrics.SizeBytes = size
	}

	
	hits, misses := getCacheHitStats()
	total := hits + misses
	if total > 0 {
		metrics.HitRate = (float64(hits) / float64(total)) * 100
	}

	
	metrics.AvgDownloadTime = getAvgDownloadTime()

	
	if metrics.HitRate > 0 && metrics.SizeBytes > 0 {
		avgSize := float64(metrics.SizeBytes) / float64(metrics.CachedVersions)
		metrics.DiskSpaceSaved = int64(float64(hits) * avgSize)
	}

	return metrics
}

func calculateTrendMetrics(analyses []Analysis) TrendMetrics {
	metrics := TrendMetrics{
		AnalysesPerDay:       make(map[string]int),
		AvgTimeByType:        make(map[string]float64),
		HistoricalVulnTrends: []VulnTrendPoint{},
	}

	timingByType := make(map[string][]float64)
	vulnsByMonth := make(map[string]int)

	for _, analysis := range analyses {
		if analysis.Meta.Status != "completed" {
			continue
		}

		
		dayKey := analysis.Meta.CreatedAt.Format("2006-01-02")
		metrics.AnalysesPerDay[dayKey]++

		
		analysisPath := filepath.Join("saved_analyses", analysis.ID+".json")
		if info, err := os.Stat(analysisPath); err == nil {
			duration := time.Since(info.ModTime()).Seconds()
			sourceType := analysis.Meta.Source
			if sourceType == "" {
				sourceType = "unknown"
			}
			timingByType[sourceType] = append(timingByType[sourceType], duration)
		}

		
		if analysis.Meta.Source == "library" || analysis.Meta.Source == "library_auto" {
			monthKey := analysis.Meta.CreatedAt.Format("2006-01")
			vulnCount := countVulnerabilities(analysis.Results)
			vulnsByMonth[monthKey] += vulnCount
		}
	}

	
	for sourceType, times := range timingByType {
		if len(times) > 0 {
			var sum float64
			for _, t := range times {
				sum += t
			}
			metrics.AvgTimeByType[sourceType] = sum / float64(len(times))
		}
	}

	
	for month, count := range vulnsByMonth {
		metrics.HistoricalVulnTrends = append(metrics.HistoricalVulnTrends, VulnTrendPoint{
			Month: month,
			Count: count,
		})
	}

	sort.Slice(metrics.HistoricalVulnTrends, func(i, j int) bool {
		return metrics.HistoricalVulnTrends[i].Month < metrics.HistoricalVulnTrends[j].Month
	})

	return metrics
}

func calculateProductMetrics(analyses []Analysis) ProductMetrics {
	metrics := ProductMetrics{
		MostAnalyzed: []ProductActivity{},
	}

	
	products := loadProducts()
	metrics.TotalConfigured = len(products)

	
	productActivity := make(map[string]int)
	for _, analysis := range analyses {
		if analysis.Meta.Status != "completed" {
			continue
		}

		if product, ok := analysis.Meta.Params["product"].(string); ok {
			productActivity[product]++
		}
	}

	
	for product, count := range productActivity {
		metrics.MostAnalyzed = append(metrics.MostAnalyzed, ProductActivity{
			Name:  product,
			Count: count,
		})
	}

	sort.Slice(metrics.MostAnalyzed, func(i, j int) bool {
		return metrics.MostAnalyzed[i].Count > metrics.MostAnalyzed[j].Count
	})

	if len(metrics.MostAnalyzed) > 10 {
		metrics.MostAnalyzed = metrics.MostAnalyzed[:10]
	}

	
	if metrics.TotalConfigured > 0 {
		totalAnalyses := 0
		for _, activity := range productActivity {
			totalAnalyses += activity
		}
		metrics.AvgCoverage = float64(totalAnalyses) / float64(metrics.TotalConfigured)
	}

	return metrics
}

func calculateSystemMetrics() SystemMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return SystemMetrics{
		MemoryMB:   m.Alloc / 1024 / 1024,
		Goroutines: runtime.NumGoroutine(),
	}
}

func calculateLanguageStats(analyses []Analysis) LanguageStats {
	stats := LanguageStats{}

	languagesByType := map[string]map[string]int{
		"products": make(map[string]int),
		"library":  make(map[string]int),
		"folder":   make(map[string]int),
	}

	for _, analysis := range analyses {
		if analysis.Meta.Status != "completed" {
			continue
		}

		sourceType := analysis.Meta.Source
		if sourceType == "library_auto" {
			sourceType = "library"
		}

		
		category := ""
		if _, ok := analysis.Meta.Params["product"]; ok {
			category = "products"
		} else if sourceType == "library" {
			category = "library"
		} else {
			category = "folder"
		}

		
		for filename := range analysis.Results {
			ext := strings.ToLower(filepath.Ext(filename))
			lang := extensionToLanguage(ext)
			if lang != "" {
				languagesByType[category][lang]++
			}
		}
	}

	
	for category, languages := range languagesByType {
		var langStats []LanguageStat
		for lang, count := range languages {
			langStats = append(langStats, LanguageStat{
				Language:  lang,
				FileCount: count,
			})
		}

		sort.Slice(langStats, func(i, j int) bool {
			return langStats[i].FileCount > langStats[j].FileCount
		})

		if len(langStats) > 5 {
			langStats = langStats[:5]
		}

		switch category {
		case "products":
			stats.Products = langStats
		case "library":
			stats.Library = langStats
		case "folder":
			stats.Folder = langStats
		}
	}

	return stats
}

func extensionToLanguage(ext string) string {
	languageMap := map[string]string{
		".php":   "PHP",
		".js":    "JavaScript",
		".jsx":   "JavaScript",
		".ts":    "TypeScript",
		".tsx":   "TypeScript",
		".py":    "Python",
		".go":    "Go",
		".java":  "Java",
		".c":     "C",
		".cpp":   "C++",
		".cc":    "C++",
		".cxx":   "C++",
		".cs":    "C#",
		".rb":    "Ruby",
		".rs":    "Rust",
		".swift": "Swift",
		".kt":    "Kotlin",
		".scala": "Scala",
		".pl":    "Perl",
		".sh":    "Shell",
		".bash":  "Shell",
		".sql":   "SQL",
		".html":  "HTML",
		".css":   "CSS",
		".vue":   "Vue",
		".dart":  "Dart",
	}

	if lang, ok := languageMap[ext]; ok {
		return lang
	}
	return ""
}


func InvalidateDashboardCache() {
	dashboardCacheMutex.Lock()
	dashboardCache = nil
	dashboardCacheMutex.Unlock()
}
