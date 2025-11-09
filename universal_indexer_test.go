package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type FunctionDefinition struct {
	Name      string `json:"name"`
	Language  string `json:"language"`
	File      string `json:"file"`
	Signature string `json:"signature"`
	Body      string `json:"body"`
	IsMethod  bool   `json:"is_method"`
	ClassName string `json:"class_name,omitempty"`
}

func DetectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".h++", ".c++", ".hh", ".ii", ".ixx":
		return "cpp"
	case ".cs", ".csx":
		return "csharp"
	case ".go":
		return "go"
	case ".java":
		return "java"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".php", ".phtml", ".php3", ".php4", ".php5", ".phps":
		return "php"
	case ".py", ".pyw", ".pyi", ".pyx":
		return "python"
	case ".rb", ".rake", ".gemspec", ".ru":
		return "ruby"
	case ".rs", ".rlib":
		return "rust"
	case ".ts", ".tsx", ".mts", ".cts":
		return "typescript"
	default:
		return "unknown"
	}
}

func ExtractFunctionContext(filePath, diffContent string, includeContext bool, repoPath string) (string, error) {
	if !includeContext {
		return "", nil
	}
	startTime := time.Now()
	language := DetectLanguage(filePath)
	if language == "unknown" {
		log.Printf("[CONTEXT] Unknown language for file: %s, skipping context extraction", filePath)
		return "", nil
	}
	functionCalls := extractFunctionCallsWithTreeSitter(filePath, diffContent, language)
	if len(functionCalls) == 0 {
		log.Printf("[CONTEXT] No function calls found in diff for %s", filePath)
		return "", nil
	}
	log.Printf("[CONTEXT] Found %d function calls in %s (repo: %s)", len(functionCalls), filepath.Base(filePath), filepath.Base(repoPath))
	
	var lazyIndex *LazyFunctionIndex
	if repoPath != "" {
		indexStart := time.Now()
		lazyIndex = NewLazyFunctionIndex(repoPath)
		indexDuration := time.Since(indexStart)
		log.Printf("[CONTEXT] Created lazy index for %s in %v", filepath.Base(repoPath), indexDuration)
	}
	builtinDetector := GetBuiltinDetector()
	type lookupTask struct {
		funcName string
		index    int
	}
	var tasks []lookupTask
	for i, funcName := range functionCalls {
		if builtinDetector.IsBuiltin(language, funcName) {
			log.Printf("[CONTEXT] Function %s.%s is a built-in, skipping context extraction", language, funcName)
			continue
		}
		tasks = append(tasks, lookupTask{funcName: funcName, index: i})
	}
	if len(tasks) == 0 {
		log.Printf("[CONTEXT] All %d functions were built-ins, no lookups needed", len(functionCalls))
		return "", nil
	}
	log.Printf("[CONTEXT] Need to lookup %d non-builtin functions", len(tasks))
	type lookupResult struct {
		def   *FunctionDefinition
		err   error
		index int
	}
	resultChan := make(chan lookupResult, len(tasks))
	var wg sync.WaitGroup
	for _, task := range tasks {
		wg.Add(1)
		go func(t lookupTask) {
			defer wg.Done()
			def, err := lookupFunctionDefinitionLazy(language, t.funcName, filePath, repoPath, lazyIndex)
			resultChan <- lookupResult{def: def, err: err, index: t.index}
		}(task)
	}
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	results := make([]*FunctionDefinition, len(functionCalls))
	for result := range resultChan {
		if result.err != nil {
			log.Printf("Could not find definition for %s.%s: %v (may be external library)",
				language, functionCalls[result.index], result.err)
			continue
		}
		if result.def != nil {
			results[result.index] = result.def
		}
	}
	definitions := make([]FunctionDefinition, 0, len(results))
	for _, def := range results {
		if def != nil {
			definitions = append(definitions, *def)
		}
	}
	if len(definitions) == 0 {
		return "", nil
	}
	context := formatFunctionContext(definitions)
	duration := time.Since(startTime)
	log.Printf("[CONTEXT] Extracted context for %s: %d/%d functions found in %v", 
		filepath.Base(filePath), len(definitions), len(tasks), duration)
	return context, nil
}

func identifyChangedFunctionsFromDiff(filePath, diffContent, language string) []string {
	var allFuncs []string
	var err error
	switch language {
	case "php":
		funcs, err1 := TSListPHPFunctions(filePath)
		if err1 == nil {
			allFuncs = append(allFuncs, funcs...)
		}
		methods, err2 := TSListPHPMethodsInFile(filePath)
		if err2 == nil {
			allFuncs = append(allFuncs, methods...)
		}
		err = err1
		if err2 != nil {
			err = err2
		}
	case "python":
		allFuncs, err = TSListPythonFunctions(filePath)
	case "c":
		allFuncs, err = TSListCFunctions(filePath)
	case "cpp":
		funcs, err1 := TSListCppFunctions(filePath)
		if err1 == nil {
			allFuncs = append(allFuncs, funcs...)
		}
		methods, err2 := TSListCppMethods(filePath)
		if err2 == nil {
			allFuncs = append(allFuncs, methods...)
		}
		err = err1
		if err2 != nil {
			err = err2
		}
	case "csharp":
		allFuncs, err = TSListCSharpMethods(filePath)
	case "go":
		allFuncs, err = TSListGoFunctions(filePath)
	case "java":
		allFuncs, err = TSListJavaMethods(filePath)
	case "javascript":
		allFuncs, err = TSListJSFunctions(filePath)
	case "ruby":
		allFuncs, err = TSListRubyMethods(filePath)
	case "rust":
		allFuncs, err = TSListRustFunctions(filePath)
	case "typescript":
		allFuncs, err = TSListTSFunctions(filePath)
	default:
		log.Printf("Unsupported language for tree-sitter function listing: %s", language)
		return []string{}
	}
	if err != nil {
		log.Printf("Error listing functions with tree-sitter: %v", err)
		return []string{}
	}
	var changedFuncs []string
	seen := make(map[string]bool)
	diffLower := strings.ToLower(diffContent)
	for _, funcName := range allFuncs {
		if seen[funcName] {
			continue
		}
		funcNameLower := strings.ToLower(funcName)
		if strings.Contains(diffLower, funcNameLower) {
			funcPattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(funcNameLower) + `\b`)
			if funcPattern.MatchString(diffLower) {
				changedFuncs = append(changedFuncs, funcName)
				seen[funcName] = true
			}
		}
	}
	return changedFuncs
}

func extractFunctionCallsWithTreeSitter(filePath, diffContent, language string) []string {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("File does not exist: %s, falling back to regex", filePath)
		return extractFunctionCallsFromDiff(diffContent, language)
	}
	changedFuncs := identifyChangedFunctionsFromDiff(filePath, diffContent, language)
	if len(changedFuncs) == 0 {
		log.Printf("No changed functions identified in diff, falling back to regex")
		return extractFunctionCallsFromDiff(diffContent, language)
	}
	var allCalls []string
	seen := make(map[string]bool)
	for _, funcName := range changedFuncs {
		var calls []string
		var err error
		switch language {
		case "php":
			calls, _, err = TSListCalledFunctionsPHPMethod(filePath, funcName)
			if err != nil {
				calls, _, err = TSListCalledFunctionsPHP(filePath, funcName)
			}
		case "python":
			calls, _, err = TSListCalledFunctionsPython(filePath, funcName)
		case "c":
			calls, _, err = TSListCalledFunctionsC(filePath, funcName)
		case "cpp":
			calls, _, err = TSListCalledFunctionsCpp(filePath, funcName)
		case "csharp":
			calls, _, err = TSListCalledFunctionsCSharp(filePath, funcName)
		case "go":
			calls, _, err = TSListCalledFunctionsGo(filePath, funcName)
		case "java":
			calls, _, err = TSListCalledFunctionsJava(filePath, funcName)
		case "javascript":
			calls, _, err = TSListCalledFunctionsJS(filePath, funcName)
		case "ruby":
			calls, _, err = TSListCalledFunctionsRuby(filePath, funcName)
		case "rust":
			calls, _, err = TSListCalledFunctionsRust(filePath, funcName)
		case "typescript":
			calls, _, err = TSListCalledFunctionsTS(filePath, funcName)
		default:
			log.Printf("Unsupported language for tree-sitter extraction: %s, falling back to regex", language)
			return extractFunctionCallsFromDiff(diffContent, language)
		}
		if err != nil {
			log.Printf("Could not extract calls from %s.%s: %v", language, funcName, err)
			continue
		}
		for _, call := range calls {
			if !seen[call] {
				allCalls = append(allCalls, call)
				seen[call] = true
			}
		}
	}
	if len(allCalls) == 0 {
		log.Printf("No function calls found via tree-sitter, falling back to regex")
		return extractFunctionCallsFromDiff(diffContent, language)
	}
	return allCalls
}

func extractFunctionCallsFromDiff(diffContent, language string) []string {
	var calls []string
	seen := make(map[string]bool)
	var patterns []*regexp.Regexp
	switch language {
	case "c", "cpp", "go", "rust":
		patterns = append(patterns, regexp.MustCompile(`\b([a-z_][a-z0-9_]*)\s*\(`))
	case "java", "csharp":
		patterns = append(patterns, regexp.MustCompile(`(?:this|[a-z][a-zA-Z0-9_]*)\s*\.\s*([a-z][a-zA-Z0-9_]*)\s*\(`))
		patterns = append(patterns, regexp.MustCompile(`\b([a-z][a-z0-9_]*)\s*\(`))
	case "javascript", "typescript":
		patterns = append(patterns, regexp.MustCompile(`(?:this|[a-z][a-zA-Z0-9_]*)\s*\.\s*([a-z][a-zA-Z0-9_]*)\s*\(`))
		patterns = append(patterns, regexp.MustCompile(`\b([a-z][a-zA-Z0-9_]*)\s*\(`))
	case "python":
		patterns = append(patterns, regexp.MustCompile(`\b([a-z_][a-z0-9_]*)\s*\(`))
		patterns = append(patterns, regexp.MustCompile(`(?:self|[a-z_][a-z0-9_]*)\s*\.\s*([a-z_][a-z0-9_]*)\s*\(`))
	case "ruby":
		patterns = append(patterns, regexp.MustCompile(`(?:[a-z_][a-z0-9_]*)\s*\.\s*([a-z_][a-z0-9_]*)`))
		patterns = append(patterns, regexp.MustCompile(`\b([a-z_][a-z0-9_]*)\s*\(`))
	case "php":
		patterns = append(patterns, regexp.MustCompile(`\$this\s*->\s*([a-z_][a-zA-Z0-9_]*)\s*\(`))
		patterns = append(patterns, regexp.MustCompile(`(?:[A-Z][a-zA-Z0-9_]*)::\s*([a-z_][a-zA-Z0-9_]*)\s*\(`))
		patterns = append(patterns, regexp.MustCompile(`\b([a-z_][a-z0-9_]*)\s*\(`))
	}
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(diffContent, -1)
		for _, match := range matches {
			if len(match) > 1 {
				funcName := match[1]
				if !seen[funcName] {
					calls = append(calls, funcName)
					seen[funcName] = true
				}
			}
		}
	}
	return calls
}


func lookupFunctionDefinitionLazy(language, funcName, currentFile, repoPath string, lazyIndex *LazyFunctionIndex) (*FunctionDefinition, error) {
	if lazyIndex != nil {
		def, err := lazyIndex.FindFunction(language, funcName)
		if err == nil && def != nil {
			return def, nil
		}
	}
	return nil, fmt.Errorf("function %s not found", funcName)
}

func formatFunctionContext(definitions []FunctionDefinition) string {
	if len(definitions) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("\n=== Function Context ===\n\n")
	builder.WriteString("The following functions are called in the changed code:\n\n")
	for i, def := range definitions {
		builder.WriteString(fmt.Sprintf("[Function: %s]\n", def.Name))
		builder.WriteString(fmt.Sprintf("Language: %s\n", def.Language))
		if def.File != "" {
			builder.WriteString(fmt.Sprintf("File: %s\n", filepath.Base(def.File)))
		}
		builder.WriteString("\n")
		if def.Body != "" {
			builder.WriteString(def.Body)
		} else if def.Signature != "" {
			builder.WriteString(def.Signature)
			builder.WriteString("\n{\n  // Function body not available\n}\n")
		}
		if i < len(definitions)-1 {
			builder.WriteString("\n---\n\n")
		}
	}
	builder.WriteString("\n=== End Function Context ===\n\n")
	return builder.String()
}
