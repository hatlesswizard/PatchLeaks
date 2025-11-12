package main
import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)
type fileCheckCacheEntry struct {
	modTime    time.Time
	funcChecks map[string]bool 
}
var (
	fileCheckCache   = make(map[string]*fileCheckCacheEntry)
	fileCheckCacheMu sync.RWMutex
)
type LazyFunctionIndex struct {
	repoPath      string
	cache         map[string]*FunctionDefinition
	mu            sync.RWMutex
	misses        map[string]bool
	missesmu      sync.RWMutex
	fileIndexOnce sync.Once
	fileIndex     map[string][]string
	fileIndexErr  error
}
func NewLazyFunctionIndex(repoPath string) *LazyFunctionIndex {
	return &LazyFunctionIndex{
		repoPath:  repoPath,
		cache:     make(map[string]*FunctionDefinition),
		misses:    make(map[string]bool),
		fileIndex: make(map[string][]string),
	}
}
func (lfi *LazyFunctionIndex) FindFunction(language, funcName string) (*FunctionDefinition, error) {
	cacheKey := language + ":" + funcName
	lfi.mu.RLock()
	if cached, exists := lfi.cache[cacheKey]; exists {
		lfi.mu.RUnlock()
		return cached, nil
	}
	lfi.mu.RUnlock()
	lfi.missesmu.RLock()
	if lfi.misses[cacheKey] {
		lfi.missesmu.RUnlock()
		return nil, fmt.Errorf("function %s not found (cached miss)", funcName)
	}
	lfi.missesmu.RUnlock()
	startTime := time.Now()
	def, err := lfi.searchAndParse(language, funcName)
	_ = time.Since(startTime)
	if err != nil || def == nil {
		lfi.missesmu.Lock()
		lfi.misses[cacheKey] = true
		lfi.missesmu.Unlock()
		return nil, fmt.Errorf("function %s not found", funcName)
	}
	lfi.mu.Lock()
	lfi.cache[cacheKey] = def
	lfi.mu.Unlock()
	return def, nil
}
func (lfi *LazyFunctionIndex) searchAndParse(language, funcName string) (*FunctionDefinition, error) {
	candidateFiles, err := lfi.findCandidateFiles(language, funcName)
	if err != nil || len(candidateFiles) == 0 {
		return nil, fmt.Errorf("no candidate files found")
	}
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
	if err := lfi.ensureFileIndex(); err != nil {
		return nil, err
	}
	extensions := getLanguageExtensions(language)
	if len(extensions) == 0 {
		return nil, fmt.Errorf("unsupported language: %s", language)
	}
	funcToken := funcName
	for _, ext := range extensions {
		files := lfi.fileIndex[ext]
		for _, path := range files {
			match, err := lfi.fileMightContainFunction(path, funcToken)
			if err != nil {
				continue
			}
			if match {
				candidates = append(candidates, path)
			}
		}
	}
	return candidates, nil
}
func (lfi *LazyFunctionIndex) parseFileForFunction(filePath, language, funcName string) (*FunctionDefinition, error) {
	switch language {
	case "php":
		
		cache, err := getOrParsePHPFile(filePath)
		if err == nil {
			
			if fn, exists := cache.funcIndex[funcName]; exists && fn != nil {
				text := string(cache.src[fn.StartByte():fn.EndByte()])
				idx := strings.Index(text, "{")
				var sig, body string
				if idx > 0 {
					sig = strings.TrimSpace(text[:idx])
					endIdx := strings.LastIndex(text, "}")
					if endIdx > idx+1 {
						body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
					}
				} else {
					sig = strings.TrimSpace(text)
				}
				return &FunctionDefinition{
					Name:      funcName,
					Language:  language,
					File:      filePath,
					Signature: sig,
					Body:      body,
					IsMethod:  false,
				}, nil
			}
			
			if md, exists := cache.methodIndex[funcName]; exists && md != nil {
				text := string(cache.src[md.StartByte():md.EndByte()])
				idx := strings.Index(text, "{")
				var sig, body string
				if idx > 0 {
					sig = strings.TrimSpace(text[:idx])
					endIdx := strings.LastIndex(text, "}")
					if endIdx > idx+1 {
						body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
					}
				} else {
					sig = strings.TrimSpace(text)
				}
				return &FunctionDefinition{
					Name:      funcName,
					Language:  language,
					File:      filePath,
					Signature: sig,
					Body:      body,
					IsMethod:  true,
				}, nil
			}
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
func (lfi *LazyFunctionIndex) ensureFileIndex() error {
	lfi.fileIndexOnce.Do(func() {
		index := make(map[string][]string)
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
			if ext == "" {
				return nil
			}
			index[ext] = append(index[ext], path)
			return nil
		})
		if err != nil {
			lfi.fileIndexErr = err
			return
		}
		lfi.fileIndex = index
	})
	return lfi.fileIndexErr
}
func (lfi *LazyFunctionIndex) fileMightContainFunction(path, funcName string) (bool, error) {
	
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	modTime := fileInfo.ModTime()
	
	fileCheckCacheMu.RLock()
	cached, exists := fileCheckCache[path]
	if exists && cached.modTime.Equal(modTime) {
		
		if result, found := cached.funcChecks[funcName]; found {
			fileCheckCacheMu.RUnlock()
			return result, nil
		}
	}
	fileCheckCacheMu.RUnlock()
	
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	found := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), funcName) {
			found = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	
	fileCheckCacheMu.Lock()
	if cached == nil || !cached.modTime.Equal(modTime) {
		
		cached = &fileCheckCacheEntry{
			modTime:    modTime,
			funcChecks: make(map[string]bool),
		}
		fileCheckCache[path] = cached
	}
	cached.funcChecks[funcName] = found
	fileCheckCacheMu.Unlock()
	return found, nil
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
