package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const UncategorizedVulnerabilityType = "Uncategorized"

type AnalysisSummary struct {
	ID                    string                   `json:"id"`
	CreatedAt             time.Time                `json:"created_at"`
	Source                string                   `json:"source"`
	Status                string                   `json:"status"`
	Product               string                   `json:"product,omitempty"`
	OldVersion            string                   `json:"old_version,omitempty"`
	NewVersion            string                   `json:"new_version,omitempty"`
	VulnerabilityCount    int                      `json:"vulnerability_count"`
	TotalFindings         int                      `json:"total_findings"`
	TopVulnerabilityTypes []VulnerabilityTypeCount `json:"top_vulnerability_types"`
	Metadata              map[string]string        `json:"metadata,omitempty"`
}

type VulnerabilityTypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type AnalysisVulnerabilityDetail struct {
	Filename            string   `json:"filename"`
	Context             []string `json:"context"`
	AIResponse          string   `json:"ai_response,omitempty"`
	VulnerabilityStatus string   `json:"vulnerability_status,omitempty"`
	StatusNormalized    string   `json:"vulnerability_status_normalized,omitempty"`
	VulnSeverity        string   `json:"vuln_severity,omitempty"`
}

func summarizeAnalysis(analysis Analysis) AnalysisSummary {
	product, oldVersion, newVersion := resolveAnalysisProductInfo(analysis)

	vulnCount := countVulnerabilities(analysis.Results)
	totalFindings := len(analysis.Results)

	topTypes := computeSortedVulnerabilityTypes(analysis.Results)
	// Show all vulnerability types, not just top 10
	// This ensures all CWEs are visible in the analysis dashboard

	metadata := map[string]string{}
	if analysis.Meta.AIService != "" {
		metadata["ai_service"] = analysis.Meta.AIService
	}
	if analysis.Meta.AIModel != "" {
		metadata["ai_model"] = analysis.Meta.AIModel
	}

	return AnalysisSummary{
		ID:                    analysis.ID,
		CreatedAt:             analysis.Meta.CreatedAt,
		Source:                analysis.Meta.Source,
		Status:                analysis.Meta.Status,
		Product:               product,
		OldVersion:            oldVersion,
		NewVersion:            newVersion,
		VulnerabilityCount:    vulnCount,
		TotalFindings:         totalFindings,
		TopVulnerabilityTypes: topTypes,
		Metadata:              metadata,
	}
}

func resolveAnalysisProductInfo(analysis Analysis) (product string, oldVersion string, newVersion string) {
	if analysis.Meta.Params == nil {
		return "", "", ""
	}
	if val, ok := analysis.Meta.Params["product"].(string); ok {
		product = val
	}
	if product == "" {
		if repo, ok := analysis.Meta.Params["repo_name"].(string); ok {
			product = repo
		}
	}
	if val, ok := analysis.Meta.Params["old_version"].(string); ok {
		oldVersion = val
	}
	if val, ok := analysis.Meta.Params["new_version"].(string); ok {
		newVersion = val
	}
	if product == "" {
		if folder, ok := analysis.Meta.Params["old_folder"].(string); ok {
			product = filepath.Base(folder)
			oldVersion = folder
		}
		if folder, ok := analysis.Meta.Params["new_folder"].(string); ok {
			if product == "" {
				product = filepath.Base(folder)
			}
			newVersion = folder
		}
	}
	return product, oldVersion, newVersion
}

func computeSortedVulnerabilityTypes(results map[string]AnalysisResult) []VulnerabilityTypeCount {
	counts := countVulnerabilityTypesFromResults(results)
	topTypes := make([]VulnerabilityTypeCount, 0, len(counts))
	for t, c := range counts {
		topTypes = append(topTypes, VulnerabilityTypeCount{
			Type:  t,
			Count: c,
		})
	}
	sort.Slice(topTypes, func(i, j int) bool {
		if topTypes[i].Count == topTypes[j].Count {
			return topTypes[i].Type < topTypes[j].Type
		}
		return topTypes[i].Count > topTypes[j].Count
	})
	return topTypes
}

func countVulnerabilityTypes(analysis Analysis) map[string]int {
	return countVulnerabilityTypesFromResults(analysis.Results)
}

func countVulnerabilityTypesFromResults(results map[string]AnalysisResult) map[string]int {
	counts := make(map[string]int)
	for _, result := range results {
		if !isRelevantResult(result) {
			continue
		}
		types := extractResultVulnerabilityTypes(result)
		if len(types) == 0 {
			counts[UncategorizedVulnerabilityType]++
			continue
		}
		seen := make(map[string]bool)
		for _, t := range types {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if !seen[t] {
				counts[t]++
				seen[t] = true
			}
		}
	}
	return counts
}

func isRelevantResult(result AnalysisResult) bool {
	normalized := strings.ToLower(getNormalizedStatus(result))
	return normalized == "yes" || normalized == "not_sure"
}

func getNormalizedStatus(result AnalysisResult) string {
	if result.VulnerabilityStatusNormalized != "" {
		return result.VulnerabilityStatusNormalized
	}
	if result.AIResponse != "" {
		_, normalized := parseAIResponseForVulnerabilities(result.AIResponse)
		if normalized != "" && normalized != "unknown" {
			return normalized
		}
	}
	status := strings.ToLower(result.VulnerabilityStatus)
	switch {
	case strings.Contains(status, "not sure"):
		return "not_sure"
	case strings.Contains(status, "no vulnerabilities"):
		return "no"
	case strings.Contains(status, "vulnerabilities"):
		return "yes"
	default:
		return "unknown"
	}
}

func extractResultVulnerabilityTypes(result AnalysisResult) []string {
	// Use the CWE field directly instead of parsing AI response
	if len(result.CWE) > 0 {
		return uniqueStrings(result.CWE)
	}
	return []string{}
}

func uniqueStrings(items []string) []string {
	if len(items) == 0 {
		return items
	}
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func buildAnalysisVulnerabilityIndex(analysis Analysis) map[string][]AnalysisVulnerabilityDetail {
	index := make(map[string][]AnalysisVulnerabilityDetail)
	for filename, result := range analysis.Results {
		if !isRelevantResult(result) {
			continue
		}
		types := extractResultVulnerabilityTypes(result)
		if len(types) == 0 {
			types = []string{UncategorizedVulnerabilityType}
		}
		detail := AnalysisVulnerabilityDetail{
			Filename:            filename,
			Context:             append([]string{}, result.Context...),
			AIResponse:          result.AIResponse,
			VulnerabilityStatus: result.VulnerabilityStatus,
			StatusNormalized:    strings.ToLower(getNormalizedStatus(result)),
			VulnSeverity:        result.VulnSeverity,
		}
		for _, t := range types {
			index[t] = append(index[t], detail)
		}
	}
	for t := range index {
		sort.Slice(index[t], func(i, j int) bool {
			return index[t][i].Filename < index[t][j].Filename
		})
	}
	return index
}

func loadAnalysisByID(id string) (*Analysis, error) {
	if !isValidUUID(id) {
		return nil, errors.New("invalid analysis id")
	}
	analysisPath := filepath.Join("saved_analyses", fmt.Sprintf("%s.json", id))
	data, err := TrackedReadFile(analysisPath)
	if err != nil {
		return nil, err
	}
	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		return nil, err
	}
	analysis.ID = id
	return &analysis, nil
}
