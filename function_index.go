package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type FunctionIndex struct {
	index map[string]map[string][]string
	mu    sync.RWMutex
}

var (
	functionIndexCache = make(map[string]*FunctionIndex)
	indexCacheMu       sync.RWMutex
	indexBuildOnce     = make(map[string]*sync.Once)
	indexBuildOnceMu   sync.Mutex
)

func GetOrBuildFunctionIndex(repoPath string) (*FunctionIndex, error) {
	if repoPath == "" {
		return nil, fmt.Errorf("repository path is empty")
	}
	indexCacheMu.RLock()
	if cached, exists := functionIndexCache[repoPath]; exists {
		indexCacheMu.RUnlock()
		log.Printf("[INDEX CACHE HIT] Using cached function index for: %s", repoPath)
		return cached, nil
	}
	indexCacheMu.RUnlock()
	indexBuildOnceMu.Lock()
	once, exists := indexBuildOnce[repoPath]
	if !exists {
		once = &sync.Once{}
		indexBuildOnce[repoPath] = once
	}
	indexBuildOnceMu.Unlock()
	var index *FunctionIndex
	var buildErr error
	once.Do(func() {
		startTime := time.Now()
		index, buildErr = BuildFunctionIndex(repoPath)
		if buildErr == nil {
			indexCacheMu.Lock()
			functionIndexCache[repoPath] = index
			indexCacheMu.Unlock()
			duration := time.Since(startTime)
			log.Printf("[INDEX CACHE STORE] Function index built and cached for %s in %v", repoPath, duration)
		}
	})
	if index == nil && buildErr == nil {
		indexCacheMu.RLock()
		index = functionIndexCache[repoPath]
		indexCacheMu.RUnlock()
	}
	return index, buildErr
}

func NewFunctionIndex() *FunctionIndex {
	return &FunctionIndex{
		index: make(map[string]map[string][]string),
	}
}

func BuildFunctionIndex(repoPath string) (*FunctionIndex, error) {
	fi := NewFunctionIndex()
	log.Printf("[INDEX] Building function index for repository: %s", repoPath)
	startTime := time.Now()
	var filePaths []string
	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			dirName := strings.ToLower(info.Name())
			if dirName == ".git" || dirName == "node_modules" || dirName == "vendor" ||
				dirName == "tests" || dirName == "__pycache__" || dirName == ".vscode" ||
				dirName == ".idea" || dirName == "target" || dirName == "build" ||
				dirName == "dist" || dirName == "bin" || dirName == "obj" {
				return filepath.SkipDir
			}
			return nil
		}
		language := DetectLanguage(path)
		if language != "unknown" {
			filePaths = append(filePaths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking repository: %v", err)
	}
	log.Printf("[INDEX] Found %d source files to index", len(filePaths))
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}
	if numWorkers > 16 {
		numWorkers = 16
	}
	log.Printf("[INDEX] Processing files with %d workers", numWorkers)
	fileChan := make(chan string, len(filePaths))
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for path := range fileChan {
				language := DetectLanguage(path)
				if language == "unknown" {
					continue
				}
				funcs := extractFunctionsFromFile(path, language)
				if len(funcs) > 0 {
					fi.mu.Lock()
					if fi.index[language] == nil {
						fi.index[language] = make(map[string][]string)
					}
					for _, funcName := range funcs {
						existing := fi.index[language][funcName]
						found := false
						for _, p := range existing {
							if p == path {
								found = true
								break
							}
						}
						if !found {
							fi.index[language][funcName] = append(existing, path)
						}
					}
					fi.mu.Unlock()
				}
			}
		}(i)
	}
	for _, path := range filePaths {
		fileChan <- path
	}
	close(fileChan)
	wg.Wait()
	totalFuncs := 0
	fi.mu.RLock()
	for _, funcMap := range fi.index {
		totalFuncs += len(funcMap)
	}
	fi.mu.RUnlock()
	duration := time.Since(startTime)
	log.Printf("[INDEX] Function index built: %d total functions across all languages in %v (%.2f files/sec)",
		totalFuncs, duration, float64(len(filePaths))/duration.Seconds())
	log.Printf("[INDEX] Performance: %.2f ms per file, %.2f functions per second",
		float64(duration.Milliseconds())/float64(len(filePaths)),
		float64(totalFuncs)/duration.Seconds())
	return fi, nil
}

func (fi *FunctionIndex) FindFunction(language, funcName string) []string {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	if langMap, exists := fi.index[language]; exists {
		if paths, found := langMap[funcName]; found {
			result := make([]string, len(paths))
			copy(result, paths)
			return result
		}
	}
	return nil
}

func extractFunctionsFromFile(filePath, language string) []string {
	var funcs []string
	var err error
	switch language {
	case "php":
		funcs1, err1 := TSListPHPFunctions(filePath)
		if err1 == nil {
			funcs = append(funcs, funcs1...)
		}
		methods, err2 := TSListPHPMethodsInFile(filePath)
		if err2 == nil {
			funcs = append(funcs, methods...)
		}
		if err1 != nil {
			err = err1
		}
		if err2 != nil {
			err = err2
		}
	case "python":
		funcs, err = TSListPythonFunctions(filePath)
	case "c":
		funcs, err = TSListCFunctions(filePath)
	case "cpp":
		funcs1, err1 := TSListCppFunctions(filePath)
		if err1 == nil {
			funcs = append(funcs, funcs1...)
		}
		methods, err2 := TSListCppMethods(filePath)
		if err2 == nil {
			funcs = append(funcs, methods...)
		}
		if err1 != nil {
			err = err1
		}
		if err2 != nil {
			err = err2
		}
	case "csharp":
		funcs, err = TSListCSharpMethods(filePath)
	case "go":
		funcs, err = TSListGoFunctions(filePath)
	case "java":
		funcs, err = TSListJavaMethods(filePath)
	case "javascript":
		funcs, err = TSListJSFunctions(filePath)
	case "ruby":
		funcs, err = TSListRubyMethods(filePath)
	case "rust":
		funcs, err = TSListRustFunctions(filePath)
	case "typescript":
		funcs, err = TSListTSFunctions(filePath)
	default:
		return []string{}
	}
	if err != nil {
		return []string{}
	}
	return funcs
}
