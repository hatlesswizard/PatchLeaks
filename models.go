package main

import (
	"encoding/json"
	"time"
)

type FlashMessage struct {
	Category string `json:"category"`
	Message  string `json:"message"`
}

type Analysis struct {
	ID          string                    `json:"id,omitempty"`
	Meta        AnalysisMeta              `json:"meta"`
	Results     map[string]AnalysisResult `json:"results"`
	VulnCount   int                       `json:"vuln_count,omitempty"`
	CVEWriteups map[string]string         `json:"cve_writeups,omitempty"`
}

type AnalysisMeta struct {
	CreatedAt  time.Time              `json:"created_at"`
	FinishedAt *time.Time             `json:"finished_at,omitempty"`
	Source     string                 `json:"source"`
	AIEnabled  bool                   `json:"ai_enabled"`
	AIService  string                 `json:"ai_service,omitempty"`
	AIModel    string                 `json:"ai_model,omitempty"`
	Status     string                 `json:"status"`
	Error      string                 `json:"error,omitempty"`
	Params     map[string]interface{} `json:"params,omitempty"`
}

type AnalysisResult struct {
	Context             []string            `json:"context"`
	AIResponse          string              `json:"ai_response,omitempty"`
	VulnerabilityStatus string              `json:"vulnerability_status,omitempty"`
	VulnSeverity        string              `json:"vuln_severity,omitempty"`
	CVEMatches          map[string]CVEMatch `json:"cve_matches,omitempty"`
}

type CVEMatch struct {
	Result      string `json:"result"`
	Description string `json:"description"`
}

type Pagination struct {
	Page        int    `json:"page"`
	PerPage     int    `json:"per_page"`
	Filter      string `json:"filter"`
	Search      string `json:"search"`
	TotalItems  int    `json:"total_items"`
	TotalPages  int    `json:"total_pages"`
	HasPrev     bool   `json:"has_prev"`
	HasNext     bool   `json:"has_next"`
	PrevPage    int    `json:"prev_page,omitempty"`
	NextPage    int    `json:"next_page,omitempty"`
	StartItem   int    `json:"start_item"`
	EndItem     int    `json:"end_item"`
	PageNumbers []int  `json:"page_numbers"`
}

type Product struct {
	RepoURL  string   `json:"repo_url"`
	Versions []string `json:"versions"`
}

type LibraryRepo struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	RepoURL     string     `json:"repo_url"`
	AIService   string     `json:"ai_service"`
	CPE         string     `json:"cpe,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	LastChecked *time.Time `json:"last_checked,omitempty"`
	LastVersion string     `json:"last_version,omitempty"`
	AutoScan    bool       `json:"auto_scan"`
}

type DiffFile struct {
	Filename string   `json:"filename"`
	Diff     []string `json:"diff"`
	Type     string   `json:"type"`
}

type VersionInfo struct {
	Version   string    `json:"version"`
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp"`
}

type CVE struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
}

func (c *CVE) UnmarshalJSON(data []byte) error {
	type NVDDescription struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}
	type TempCVE struct {
		ID           string           `json:"id"`
		Descriptions []NVDDescription `json:"descriptions"`
		Published    string           `json:"published"`
		LastModified string           `json:"lastModified"`
	}
	var temp TempCVE
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	c.ID = temp.ID
	for _, desc := range temp.Descriptions {
		if desc.Lang == "en" {
			c.Description = desc.Value
			break
		}
	}
	if c.Description == "" && len(temp.Descriptions) > 0 {
		c.Description = temp.Descriptions[0].Value
	}
	c.Published = parseNVDate(temp.Published)
	c.Modified = parseNVDate(temp.LastModified)
	c.Severity = "UNKNOWN"
	return nil
}

func parseNVDate(dateStr string) time.Time {
	if dateStr == "" {
		return time.Time{}
	}
	formats := []string{
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05.000-07:00",
		"2006-01-02T15:04:05-07:00",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t
		}
	}
	return time.Time{}
}

type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE CVE `json:"cve"`
	} `json:"vulnerabilities"`
}
