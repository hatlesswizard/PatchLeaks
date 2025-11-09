package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)


func TestIndexPerformanceSmallRepo(t *testing.T) {
	repoPath := "cache/cobra_go_1_7_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found, skipping", repoPath)
	}

	t.Logf("Testing small repo: %s", repoPath)
	fileCount := countSourceFiles(repoPath)
	t.Logf("Source files in repo: %d", fileCount)

	startTime := time.Now()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	index, err := BuildFunctionIndex(repoPath)
	if err != nil {
		t.Fatalf("Failed to build index: %v", err)
	}

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	duration := time.Since(startTime)

	funcCount := 0
	index.mu.RLock()
	for _, langMap := range index.index {
		funcCount += len(langMap)
	}
	index.mu.RUnlock()

	memUsed := memAfter.Alloc - memBefore.Alloc

	t.Logf("=== SMALL REPO RESULTS ===")
	t.Logf("Files indexed: %d", fileCount)
	t.Logf("Functions found: %d", funcCount)
	t.Logf("Time taken: %v", duration)
	t.Logf("Memory used: %.2f MB", float64(memUsed)/(1024*1024))
	t.Logf("Files/sec: %.2f", float64(fileCount)/duration.Seconds())
}


func TestIndexPerformanceMediumRepo(t *testing.T) {
	repoPath := "cache/gin_go_1_9_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found, skipping", repoPath)
	}

	t.Logf("Testing medium repo: %s", repoPath)
	fileCount := countSourceFiles(repoPath)
	t.Logf("Source files in repo: %d", fileCount)

	startTime := time.Now()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	index, err := BuildFunctionIndex(repoPath)
	if err != nil {
		t.Fatalf("Failed to build index: %v", err)
	}

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	duration := time.Since(startTime)

	funcCount := 0
	index.mu.RLock()
	for _, langMap := range index.index {
		funcCount += len(langMap)
	}
	index.mu.RUnlock()

	memUsed := memAfter.Alloc - memBefore.Alloc

	t.Logf("=== MEDIUM REPO RESULTS ===")
	t.Logf("Files indexed: %d", fileCount)
	t.Logf("Functions found: %d", funcCount)
	t.Logf("Time taken: %v", duration)
	t.Logf("Memory used: %.2f MB", float64(memUsed)/(1024*1024))
	t.Logf("Files/sec: %.2f", float64(fileCount)/duration.Seconds())
}


func TestIndexPerformanceLargeRepo(t *testing.T) {
	repoPath := "cache/guava_java_32_1_1"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found, skipping", repoPath)
	}

	t.Logf("Testing large repo: %s", repoPath)
	fileCount := countSourceFiles(repoPath)
	t.Logf("Source files in repo: %d", fileCount)

	startTime := time.Now()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	index, err := BuildFunctionIndex(repoPath)
	if err != nil {
		t.Fatalf("Failed to build index: %v", err)
	}

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	duration := time.Since(startTime)

	funcCount := 0
	index.mu.RLock()
	for _, langMap := range index.index {
		funcCount += len(langMap)
	}
	index.mu.RUnlock()

	memUsed := memAfter.Alloc - memBefore.Alloc

	t.Logf("=== LARGE REPO RESULTS ===")
	t.Logf("Files indexed: %d", fileCount)
	t.Logf("Functions found: %d", funcCount)
	t.Logf("Time taken: %v", duration)
	t.Logf("Memory used: %.2f MB", float64(memUsed)/(1024*1024))
	t.Logf("Files/sec: %.2f", float64(fileCount)/duration.Seconds())

	if duration.Seconds() > 60 {
		t.Logf("WARNING: Indexing took over 1 minute for %d files!", fileCount)
	}
}


func TestSingleFileParsingCost(t *testing.T) {
	testCases := []struct {
		name     string
		repoPath string
		filePath string
		language string
	}{
		{
			name:     "Small Go file",
			repoPath: "cache/cobra_go_1_7_0",
			filePath: "cache/cobra_go_1_7_0/cobra.go",
			language: "go",
		},
		{
			name:     "Medium Go file",
			repoPath: "cache/gin_go_1_9_0",
			filePath: "cache/gin_go_1_9_0/context.go",
			language: "go",
		},
		{
			name:     "Large Java file",
			repoPath: "cache/guava_java_32_1_1",
			filePath: "", 
			language: "java",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := os.Stat(tc.repoPath); os.IsNotExist(err) {
				t.Skipf("Test repo %s not found", tc.repoPath)
			}

			
			filePath := tc.filePath
			if filePath == "" {
				filepath.Walk(tc.repoPath, func(path string, info os.FileInfo, err error) error {
					if err == nil && !info.IsDir() && DetectLanguage(path) == tc.language {
						filePath = path
						return filepath.SkipAll
					}
					return nil
				})
			}

			if filePath == "" || !fileExists(filePath) {
				t.Skipf("No suitable file found")
			}

			fileInfo, _ := os.Stat(filePath)
			fileSize := fileInfo.Size()

			
			readStart := time.Now()
			content, err := os.ReadFile(filePath)
			readDuration := time.Since(readStart)
			if err != nil {
				t.Fatalf("Failed to read file: %v", err)
			}

			
			parseStart := time.Now()
			funcs := extractFunctionsFromFile(filePath, tc.language)
			parseDuration := time.Since(parseStart)

			t.Logf("File: %s", filepath.Base(filePath))
			t.Logf("Size: %.2f KB", float64(fileSize)/1024)
			t.Logf("Lines: %d", len(content)/50) 
			t.Logf("Functions found: %d", len(funcs))
			t.Logf("Read time: %v", readDuration)
			t.Logf("Parse time: %v", parseDuration)
			t.Logf("Parse/Read ratio: %.2fx", parseDuration.Seconds()/readDuration.Seconds())
		})
	}
}


func TestBatchParsingPerformance(t *testing.T) {
	repoPath := "cache/gin_go_1_9_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found", repoPath)
	}

	var files []string
	filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && DetectLanguage(path) == "go" {
			files = append(files, path)
		}
		return nil
	})

	testSizes := []int{10, 50, 100}

	for _, size := range testSizes {
		if size > len(files) {
			continue
		}

		testFiles := files[:size]

		t.Run(fmt.Sprintf("Parse_%d_files", size), func(t *testing.T) {
			startTime := time.Now()

			totalFuncs := 0
			for _, file := range testFiles {
				funcs := extractFunctionsFromFile(file, "go")
				totalFuncs += len(funcs)
			}

			duration := time.Since(startTime)

			t.Logf("Parsed %d files", size)
			t.Logf("Found %d functions", totalFuncs)
			t.Logf("Time: %v", duration)
			t.Logf("Time per file: %v", duration/time.Duration(size))
			t.Logf("Files/sec: %.2f", float64(size)/duration.Seconds())
		})
	}
}


func TestIndexCachingBehavior(t *testing.T) {
	repoPath := "cache/cobra_go_1_7_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found", repoPath)
	}

	
	indexCacheMu.Lock()
	delete(functionIndexCache, repoPath)
	delete(indexBuildOnce, repoPath)
	indexCacheMu.Unlock()

	
	t.Log("First index build (should build from scratch)...")
	start1 := time.Now()
	index1, err := GetOrBuildFunctionIndex(repoPath)
	duration1 := time.Since(start1)
	if err != nil {
		t.Fatalf("First build failed: %v", err)
	}

	
	t.Log("Second index build (should use cache)...")
	start2 := time.Now()
	index2, err := GetOrBuildFunctionIndex(repoPath)
	duration2 := time.Since(start2)
	if err != nil {
		t.Fatalf("Second build failed: %v", err)
	}

	t.Logf("First build time: %v", duration1)
	t.Logf("Second build time: %v", duration2)
	t.Logf("Speedup: %.2fx", duration1.Seconds()/duration2.Seconds())

	if index1 != index2 {
		t.Errorf("Cache not working: different index instances returned")
	}

	if duration2 > duration1/10 {
		t.Errorf("Cache not effective: second build took %v (expected < %v)", duration2, duration1/10)
	}
}


func TestRealWorldScenario(t *testing.T) {
	repoPath := "cache/gin_go_1_9_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found", repoPath)
	}

	
	indexCacheMu.Lock()
	delete(functionIndexCache, repoPath)
	delete(indexBuildOnce, repoPath)
	indexCacheMu.Unlock()

	
	changedFiles := 80
	fileCount := countSourceFiles(repoPath)

	t.Logf("=== REAL WORLD SCENARIO ===")
	t.Logf("Total files in repo: %d", fileCount)
	t.Logf("Simulating analysis of %d changed files", changedFiles)

	startTime := time.Now()

	
	for i := 0; i < changedFiles; i++ {
		
		_, err := GetOrBuildFunctionIndex(repoPath)
		if err != nil {
			t.Fatalf("Failed to get index: %v", err)
		}

		if i == 0 {
			firstCallTime := time.Since(startTime)
			t.Logf("First call (builds index): %v", firstCallTime)
			if firstCallTime.Seconds() > 10 {
				t.Logf("WARNING: First call took over 10 seconds!")
			}
		}
	}

	totalTime := time.Since(startTime)
	avgTimePerFile := totalTime / time.Duration(changedFiles)

	t.Logf("Total time: %v", totalTime)
	t.Logf("Average time per changed file: %v", avgTimePerFile)
	t.Logf("Throughput: %.2f files/sec", float64(changedFiles)/totalTime.Seconds())

	
	if totalTime.Seconds() > 15 {
		t.Logf("PERFORMANCE ISSUE DETECTED:")
		t.Logf("Processing %d changed files took %v", changedFiles, totalTime)
		t.Logf("This suggests index is being rebuilt multiple times or cache is not working")
	}
}


func TestIndexRebuildCount(t *testing.T) {
	repoPath := "cache/cobra_go_1_7_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found", repoPath)
	}

	
	indexCacheMu.Lock()
	delete(functionIndexCache, repoPath)
	delete(indexBuildOnce, repoPath)
	indexCacheMu.Unlock()

	buildCount := 0
	originalLog := log.Writer()
	defer log.SetOutput(originalLog)

	
	logFile, err := os.CreateTemp("", "index_test_*.log")
	if err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}
	defer os.Remove(logFile.Name())
	log.SetOutput(logFile)

	
	for i := 0; i < 10; i++ {
		_, err := GetOrBuildFunctionIndex(repoPath)
		if err != nil {
			t.Fatalf("Failed to get index: %v", err)
		}
	}

	log.SetOutput(originalLog)
	logFile.Close()

	
	logContent, _ := os.ReadFile(logFile.Name())
	logStr := string(logContent)
	
	
	if count := countSubstring(logStr, "Function index built"); count > 0 {
		buildCount = count
	}

	t.Logf("GetOrBuildFunctionIndex called: 10 times")
	t.Logf("Actual index builds: %d", buildCount)

	if buildCount > 1 {
		t.Errorf("CACHING ISSUE: Index was built %d times (expected 1)", buildCount)
	} else if buildCount == 1 {
		t.Logf("SUCCESS: Cache working correctly (only 1 build)")
	}
}



func countSourceFiles(repoPath string) int {
	count := 0
	filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if DetectLanguage(path) != "unknown" {
			count++
		}
		return nil
	})
	return count
}

func countSubstring(s, substr string) int {
	count := 0
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			count++
		}
	}
	return count
}


func BenchmarkFullIndexBuild(b *testing.B) {
	repoPath := "cache/cobra_go_1_7_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		b.Skip("Test repo not found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		
		indexCacheMu.Lock()
		delete(functionIndexCache, repoPath)
		delete(indexBuildOnce, repoPath)
		indexCacheMu.Unlock()

		_, err := BuildFunctionIndex(repoPath)
		if err != nil {
			b.Fatalf("Failed to build index: %v", err)
		}
	}
}


func BenchmarkCachedIndexLookup(b *testing.B) {
	repoPath := "cache/cobra_go_1_7_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		b.Skip("Test repo not found")
	}

	
	index, err := GetOrBuildFunctionIndex(repoPath)
	if err != nil {
		b.Fatalf("Failed to build index: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		
		index.FindFunction("go", "Execute")
	}
}

