package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)


type LazyFunctionIndex struct {
	repoPath string
	cache    map[string]*FunctionDefinition 
	mu       sync.RWMutex
	misses   map[string]bool 
	missesmu sync.RWMutex
}

func NewLazyFunctionIndex(repoPath string) *LazyFunctionIndex {
	return &LazyFunctionIndex{
		repoPath: repoPath,
		cache:    make(map[string]*FunctionDefinition),
		misses:   make(map[string]bool),
	}
}


func (lfi *LazyFunctionIndex) FindFunction(language, funcName string) (*FunctionDefinition, error) {
	cacheKey := language + ":" + funcName

	
	lfi.mu.RLock()
	if cached, exists := lfi.cache[cacheKey]; exists {
		lfi.mu.RUnlock()
		log.Printf("[LAZY INDEX] Cache hit for %s.%s", language, funcName)
		return cached, nil
	}
	lfi.mu.RUnlock()

	
	lfi.missesmu.RLock()
	if lfi.misses[cacheKey] {
		lfi.missesmu.RUnlock()
		log.Printf("[LAZY INDEX] Known miss for %s.%s", language, funcName)
		return nil, fmt.Errorf("function %s not found (cached miss)", funcName)
	}
	lfi.missesmu.RUnlock()

	
	startTime := time.Now()
	def, err := lfi.searchAndParse(language, funcName)
	duration := time.Since(startTime)

	if err != nil || def == nil {
		
		lfi.missesmu.Lock()
		lfi.misses[cacheKey] = true
		lfi.missesmu.Unlock()
		log.Printf("[LAZY INDEX] Function %s.%s not found after %v", language, funcName, duration)
		return nil, fmt.Errorf("function %s not found", funcName)
	}

	
	lfi.mu.Lock()
	lfi.cache[cacheKey] = def
	lfi.mu.Unlock()

	log.Printf("[LAZY INDEX] Found %s.%s in %s (took %v)", language, funcName, def.File, duration)
	return def, nil
}


func (lfi *LazyFunctionIndex) searchAndParse(language, funcName string) (*FunctionDefinition, error) {
	
	candidateFiles, err := lfi.findCandidateFiles(language, funcName)
	if err != nil || len(candidateFiles) == 0 {
		return nil, fmt.Errorf("no candidate files found")
	}

	log.Printf("[LAZY INDEX] Found %d candidate files for %s.%s", len(candidateFiles), language, funcName)

	
	for _, filePath := range candidateFiles {
		def, err := lfi.parseFileForFunction(filePath, language, funcName)
		if err == nil && def != nil {
			return def, nil
		}
	}

	return nil, fmt.Errorf("function not found in any candidate file")
}


func (lfi *LazyFunctionIndex) findCandidateFiles(language, funcName string) ([]string, error) {
	var candidates []string
	
	
	extensions := getLanguageExtensions(language)
	if len(extensions) == 0 {
		return nil, fmt.Errorf("unsupported language: %s", language)
	}

	
	
	err := filepath.Walk(lfi.repoPath, func(path string, info os.FileInfo, err error) error {
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

		
		ext := strings.ToLower(filepath.Ext(path))
		validExt := false
		for _, validExtension := range extensions {
			if ext == validExtension {
				validExt = true
				break
			}
		}
		if !validExt {
			return nil
		}

		
		
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		if strings.Contains(string(content), funcName) {
			candidates = append(candidates, path)
		}

		return nil
	})

	return candidates, err
}


func (lfi *LazyFunctionIndex) parseFileForFunction(filePath, language, funcName string) (*FunctionDefinition, error) {
	
	switch language {
	case "php":
		
		sig, body, err := TSFindPHPFunction(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
				IsMethod:  false,
			}, nil
		}
		
		sig, body, err = TSFindPHPMethod(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
				IsMethod:  true,
			}, nil
		}

	case "python":
		sig, body, err := TSFindPythonFunction(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
			}, nil
		}

	case "c":
		sig, body, err := TSFindCFunction(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
			}, nil
		}

	case "cpp":
		
		sig, body, err := TSFindCppFunction(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
				IsMethod:  false,
			}, nil
		}
		
		sig, body, err = TSFindCppMethod(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
				IsMethod:  true,
			}, nil
		}

	case "csharp":
		sig, body, err := TSFindCSharpMethod(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
				IsMethod:  true,
			}, nil
		}

	case "go":
		sig, body, err := TSFindGoFunction(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
			}, nil
		}

	case "java":
		sig, body, err := TSFindJavaMethod(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
				IsMethod:  true,
			}, nil
		}

	case "javascript":
		sig, body, err := TSFindJSFunction(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
			}, nil
		}

	case "ruby":
		sig, body, err := TSFindRubyMethod(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
				IsMethod:  true,
			}, nil
		}

	case "rust":
		sig, body, err := TSFindRustFunction(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
			}, nil
		}

	case "typescript":
		sig, body, err := TSFindTSFunction(filePath, funcName)
		if err == nil {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      filePath,
				Signature: sig,
				Body:      body,
			}, nil
		}
	}

	return nil, fmt.Errorf("function %s not found in %s", funcName, filePath)
}


func getLanguageExtensions(language string) []string {
	switch language {
	case "php":
		return []string{".php", ".phtml", ".php3", ".php4", ".php5", ".phps"}
	case "javascript":
		return []string{".js", ".jsx", ".mjs", ".cjs"}
	case "typescript":
		return []string{".ts", ".tsx", ".mts", ".cts"}
	case "python":
		return []string{".py", ".pyw", ".pyi", ".pyx"}
	case "java":
		return []string{".java"}
	case "go":
		return []string{".go"}
	case "ruby":
		return []string{".rb", ".rake", ".gemspec", ".ru"}
	case "c":
		return []string{".c", ".h"}
	case "cpp":
		return []string{".cpp", ".hpp", ".cc", ".cxx", ".h++", ".c++", ".hh"}
	case "csharp":
		return []string{".cs", ".csx"}
	case "rust":
		return []string{".rs", ".rlib"}
	default:
		return []string{}
	}
}


func (lfi *LazyFunctionIndex) GetCacheStats() (hits int, misses int) {
	lfi.mu.RLock()
	hits = len(lfi.cache)
	lfi.mu.RUnlock()

	lfi.missesmu.RLock()
	misses = len(lfi.misses)
	lfi.missesmu.RUnlock()

	return hits, misses
}

