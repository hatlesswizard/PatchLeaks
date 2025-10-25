package main

import (
	"encoding/json"
	"time"
)

// FlashMessage represents a flash message (for future implementation)
type FlashMessage struct {
	Category string `json:"category"`
	Message  string `json:"message"`
}

// Analysis represents a complete analysis record
type Analysis struct {
	ID        string                    `json:"id,omitempty"`
	Meta      AnalysisMeta              `json:"meta"`
	Results   map[string]AnalysisResult `json:"results"`
	VulnCount int                       `json:"vuln_count,omitempty"`
}

// AnalysisMeta contains metadata about an analysis
type AnalysisMeta struct {
	CreatedAt time.Time              `json:"created_at"`
	Source    string                 `json:"source"`
	AIEnabled bool                   `json:"ai_enabled"`
	AIService string                 `json:"ai_service,omitempty"`
	AIModel   string                 `json:"ai_model,omitempty"`
	Status    string                 `json:"status"`
	Error     string                 `json:"error,omitempty"`
	Params    map[string]interface{} `json:"params,omitempty"`
}

// AnalysisResult represents the result for a single file
type AnalysisResult struct {
	Context              []string               `json:"context"`
	AIResponse           string                 `json:"ai_response,omitempty"`
	VulnerabilityStatus  string                 `json:"vulnerability_status,omitempty"`
	VulnSeverity         string                 `json:"vuln_severity,omitempty"`
	CVEMatches           map[string]CVEMatch    `json:"cve_matches,omitempty"`
}

// CVEMatch represents a CVE match result
type CVEMatch struct {
	Result      string `json:"result"`
	Description string `json:"description"`
}

// Pagination represents pagination data
type Pagination struct {
	Page       int    `json:"page"`
	PerPage    int    `json:"per_page"`
	Filter     string `json:"filter"`
	Search     string `json:"search"`
	TotalItems int    `json:"total_items"`
	TotalPages int    `json:"total_pages"`
	HasPrev    bool   `json:"has_prev"`
	HasNext    bool   `json:"has_next"`
	PrevPage   int    `json:"prev_page,omitempty"`
	NextPage   int    `json:"next_page,omitempty"`
	StartItem  int    `json:"start_item"`
	EndItem    int    `json:"end_item"`
	PageNumbers []int `json:"page_numbers"`
}

// Product represents a product configuration
type Product struct {
	RepoURL  string   `json:"repo_url"`
	Versions []string `json:"versions"`
}

// LibraryRepo represents a library repository
type LibraryRepo struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	RepoURL      string    `json:"repo_url"`
	AIService    string    `json:"ai_service"`
	CPE          string    `json:"cpe,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	LastChecked  *time.Time `json:"last_checked,omitempty"`
	LastVersion  string    `json:"last_version,omitempty"`
	AutoScan     bool      `json:"auto_scan"`
}

// DiffFile represents a file with differences
type DiffFile struct {
	Filename string   `json:"filename"`
	Diff     []string `json:"diff"`
	Type     string   `json:"type"` // modified, added, deleted
}

// BenchmarkResult represents AI benchmark results
type BenchmarkResult struct {
	BenchmarkID string                 `json:"benchmark_id"`
	Status      string                 `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	Config      map[string]interface{} `json:"config"`
	Results     map[string][]QuestionResult `json:"results"`
	Metrics     map[string]BenchmarkMetrics `json:"metrics"`
	Progress    float64                `json:"progress,omitempty"`
	CurrentTest string                 `json:"current_test,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// QuestionResult represents the result of a single benchmark question
type QuestionResult struct {
	QuestionID     int     `json:"question_id"`
	Question       string  `json:"question"`
	ExpectedAnswer string  `json:"expected_answer"`
	AIResponse     string  `json:"ai_response"`
	ResponseTime   float64 `json:"response_time"`
	ResponseLength int     `json:"response_length"`
	AccuracyScore  float64 `json:"accuracy_score"`
	AccuracyBinary bool    `json:"accuracy_binary"`
	JudgeAI        string  `json:"judge_ai"`
	Error          string  `json:"error,omitempty"`
}

// BenchmarkMetrics represents metrics for a benchmark
type BenchmarkMetrics struct {
	TotalQuestions     int     `json:"total_questions"`
	AvgResponseTime    float64 `json:"avg_response_time"`
	AvgResponseLength  float64 `json:"avg_response_length"`
	AvgAccuracyScore   float64 `json:"avg_accuracy_score"`
	AccuracyRate       float64 `json:"accuracy_rate"`
	CorrectAnswers     int     `json:"correct_answers"`
	TotalResponseTime  float64 `json:"total_response_time"`
}

// VersionInfo represents version information for a product
type VersionInfo struct {
	Version   string    `json:"version"`
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp"`
}

// CVE represents a CVE entry from NVD
type CVE struct {
	ID          string    `json:"id"`
	Description string    `json:"description"` // Populated from descriptions array
	Severity    string    `json:"severity"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
}

// UnmarshalJSON custom unmarshaling for CVE to match NVD API v2.0 format
func (c *CVE) UnmarshalJSON(data []byte) error {
	// NVD API v2.0 structure
	type NVDDescription struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}
	
	type TempCVE struct {
		ID           string           `json:"id"`
		Descriptions []NVDDescription `json:"descriptions"` // NVD uses array
		Published    string           `json:"published"`
		LastModified string           `json:"lastModified"` // NVD uses lastModified
	}
	
	var temp TempCVE
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	
	c.ID = temp.ID
	
	// Extract English description from descriptions array
	for _, desc := range temp.Descriptions {
		if desc.Lang == "en" {
			c.Description = desc.Value
			break
		}
	}
	// Fallback to first description if no English found
	if c.Description == "" && len(temp.Descriptions) > 0 {
		c.Description = temp.Descriptions[0].Value
	}
	
	// Parse dates with multiple possible formats
	c.Published = parseNVDate(temp.Published)
	c.Modified = parseNVDate(temp.LastModified)
	
	// TODO: Extract severity from metrics if needed
	c.Severity = "UNKNOWN"
	
	return nil
}

// parseNVDate parses NVD date strings in various formats
func parseNVDate(dateStr string) time.Time {
	if dateStr == "" {
		return time.Time{}
	}
	
	// Try different date formats that NVD might use
	formats := []string{
		"2006-01-02T15:04:05.000",           // 2007-10-03T14:17:00.000
		"2006-01-02T15:04:05.000Z",          // With Z suffix
		"2006-01-02T15:04:05Z",              // Without milliseconds
		"2006-01-02T15:04:05",               // Basic format
		"2006-01-02T15:04:05.000-07:00",     // With timezone
		"2006-01-02T15:04:05-07:00",         // Without milliseconds, with timezone
	}
	
	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t
		}
	}
	
	// If all formats fail, return zero time
	return time.Time{}
}

// NVDResponse represents the response from NVD API
type NVDResponse struct {
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE CVE `json:"cve"`
	} `json:"vulnerabilities"`
}

