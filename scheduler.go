package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

func startScheduler() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	go checkForNewVersions()

	for range ticker.C {
		go checkForNewVersions()
	}
}

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

		versions := getGitHubVersionsByDate(repo.RepoURL)
		if len(versions) == 0 {
			continue
		}

		var nextVersion string
		if repo.LastVersion == "" {
			nextVersion = versions[0]
		} else {
			nextVersion = getNextIncrementalVersion(repo.LastVersion, versions)
		}
		
		if repo.LastVersion != nextVersion {
			log.Printf("New version detected for %s: %s → %s", repo.Name, repo.LastVersion, nextVersion)
			
			if repo.LastVersion != "" {
				triggerAutoAnalysis(repo, repo.LastVersion, nextVersion)
			}
			
			now := time.Now()
			library[i].LastChecked = &now
			library[i].LastVersion = nextVersion
		} else {
			now := time.Now()
			library[i].LastChecked = &now
		}
	}

	saveLibrary(library)
	log.Println("Version check completed")
}

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

func runLibraryAnalysisBackground(analysisID string, params map[string]interface{}, analysisMode string) {
	analysisPath := filepath.Join("saved_analyses", analysisID+".json")
	
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Library analysis %s panicked: %v", analysisID, r)
			updateAnalysisStatus(analysisPath, "failed", fmt.Sprintf("%v", r))
		}
	}()

	log.Printf("Library analysis %s started (mode: %s)", analysisID, analysisMode)
	
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

	analysis.Meta.Status = "completed"
	analysis.Results = results
	
	analysis.Meta.Params = params
	
	if params["enable_ai"] == "on" {
		aiConfig, _ := LoadConfig()
		if aiConfig != nil {
			analysis.Meta.AIService = aiConfig.Service
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

	data, _ = json.MarshalIndent(analysis, "", "  ")
	if err := os.WriteFile(analysisPath, data, 0644); err != nil {
		log.Printf("Failed to save analysis: %v", err)
		return
	}
	
	log.Printf("Library analysis %s completed with %d results", analysisID, len(results))
}

