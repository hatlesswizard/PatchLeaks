package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// startScheduler starts the background scheduler for version checking
func startScheduler() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	// Run immediately on start
	go checkForNewVersions()

	for range ticker.C {
		go checkForNewVersions()
	}
}

// checkForNewVersions checks for new versions in the library
func checkForNewVersions() {
	log.Println("Checking for new versions in library")
	
	library := loadLibrary()
	
	for i, repo := range library {
		if !repo.AutoScan {
			continue
		}

		if !validateURL(repo.RepoURL) {
			continue
		}

		versions := getGitHubVersions(repo.RepoURL)
		if len(versions) == 0 {
			continue
		}

		// Use smart version detection: prefer incremental versions (p1→p2) over major jumps
		var nextVersion string
		if repo.LastVersion == "" {
			// First time, use latest
			nextVersion = versions[0]
		} else {
			// Find next incremental version or next major version
			nextVersion = getNextIncrementalVersion(repo.LastVersion, versions)
		}
		
		// Check if version has changed
		if repo.LastVersion != nextVersion {
			log.Printf("New version detected for %s: %s → %s", repo.Name, repo.LastVersion, nextVersion)
			
			// Trigger auto-analysis if this isn't the first version
			if repo.LastVersion != "" {
				triggerAutoAnalysis(repo, repo.LastVersion, nextVersion)
			}
			
			// Update repository
			now := time.Now()
			library[i].LastChecked = &now
			library[i].LastVersion = nextVersion
		} else {
			// Just update last checked time
			now := time.Now()
			library[i].LastChecked = &now
		}
	}

	// Save updated library
	saveLibrary(library)
	log.Println("Version check completed")
}

// triggerAutoAnalysis triggers automatic analysis for a repository
func triggerAutoAnalysis(repo LibraryRepo, oldVersion, newVersion string) {
	if !validateVersion(oldVersion) || !validateVersion(newVersion) {
		log.Printf("Invalid versions for %s: %s -> %s", repo.Name, oldVersion, newVersion)
		return
	}

	params := map[string]interface{}{
		"repo_name":        repo.Name,
		"repo_url":         repo.RepoURL,
		"old_version":      oldVersion,
		"new_version":      newVersion,
		"ai_service":       repo.AIService,
		"extension":        nil,
		"enable_ai":        "on",
		"special_keywords": "",
		"cve_ids":          "",
	}

	// Use CVE-based analysis if CPE is available
	analysisMode := "library_auto"
	if repo.CPE != "" {
		params["cpe"] = repo.CPE
		analysisMode = "cve_auto"
		log.Printf("Using CVE-based analysis for %s (CPE: %s)", repo.Name, repo.CPE)
	}

	analysisID := createNewAnalysisRecord(params, analysisMode, true)
	go runLibraryAnalysisBackground(analysisID, params, analysisMode)

	log.Printf("Auto-analysis triggered for %s (%s → %s) using %s mode", repo.Name, oldVersion, newVersion, analysisMode)
}

// runLibraryAnalysisBackground runs library analysis in the background
func runLibraryAnalysisBackground(analysisID string, params map[string]interface{}, analysisMode string) {
	analysisPath := filepath.Join("saved_analyses", analysisID+".json")
	
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Library analysis %s panicked: %v", analysisID, r)
			updateAnalysisStatus(analysisPath, "failed", fmt.Sprintf("%v", r))
		}
	}()

	log.Printf("Library analysis %s started (mode: %s)", analysisID, analysisMode)
	
	// Use appropriate analysis function based on mode
	var results map[string]AnalysisResult
	switch analysisMode {
	case "cve_auto":
		results = runCVEBasedAnalysis(analysisID, params)
	case "library_auto":
		results = runLibraryAnalysis(params)
	default:
		log.Printf("Unknown analysis mode: %s, falling back to library analysis", analysisMode)
		results = runLibraryAnalysis(params)
	}
	
	// Load existing analysis
	data, err := os.ReadFile(analysisPath)
	if err != nil {
		log.Printf("Failed to read analysis file: %v", err)
		updateAnalysisStatus(analysisPath, "failed", err.Error())
		return
	}

	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		log.Printf("Failed to unmarshal analysis: %v", err)
		updateAnalysisStatus(analysisPath, "failed", err.Error())
		return
	}

	// Update with results
	analysis.Meta.Status = "completed"
	analysis.Results = results
	
	// Update params with any changes from analysis (e.g., CVE IDs fetched during analysis)
	analysis.Meta.Params = params
	
	// Update AI service and model info if AI was enabled
	if params["enable_ai"] == "on" {
		aiConfig, _ := LoadConfig()
		if aiConfig != nil {
			analysis.Meta.AIService = aiConfig.Service
			// Get model based on service
			switch aiConfig.Service {
			case "ollama":
				if model, ok := aiConfig.Ollama["model"].(string); ok {
					analysis.Meta.AIModel = model
				}
			case "openai":
				if model, ok := aiConfig.OpenAI["model"].(string); ok {
					analysis.Meta.AIModel = model
				}
			case "deepseek":
				if model, ok := aiConfig.DeepSeek["model"].(string); ok {
					analysis.Meta.AIModel = model
				}
			case "claude":
				if model, ok := aiConfig.Claude["model"].(string); ok {
					analysis.Meta.AIModel = model
				}
			}
		}
	}

	// Save final analysis
	data, _ = json.MarshalIndent(analysis, "", "  ")
	if err := os.WriteFile(analysisPath, data, 0644); err != nil {
		log.Printf("Failed to save analysis: %v", err)
		return
	}
	
	log.Printf("Library analysis %s completed with %d results", analysisID, len(results))
}

