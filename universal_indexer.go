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
		log.Printf("Unknown language for file: %s, skipping context extraction", filePath)
		return "", nil
	}
	functionCalls := extractFunctionCallsWithTreeSitter(filePath, diffContent, language)
	if len(functionCalls) == 0 {
		log.Printf("No function calls found in diff for %s", filePath)
		return "", nil
	}
	log.Printf("Found %d function calls in %s", len(functionCalls), filepath.Base(filePath))
	var funcIndex *FunctionIndex
	if repoPath != "" {
		var err error
		funcIndex, err = GetOrBuildFunctionIndex(repoPath)
		if err != nil {
			log.Printf("Warning: Could not get function index for %s: %v", repoPath, err)
		}
	}
	builtinDetector := GetBuiltinDetector()
	type lookupTask struct {
		funcName string
		index    int
	}
	var tasks []lookupTask
	for i, funcName := range functionCalls {
		if builtinDetector.IsBuiltin(language, funcName) {
			log.Printf("Function %s.%s is a built-in, skipping context extraction", language, funcName)
			continue
		}
		tasks = append(tasks, lookupTask{funcName: funcName, index: i})
	}
	if len(tasks) == 0 {
		return "", nil
	}
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
			def, err := lookupFunctionDefinition(language, t.funcName, filePath, repoPath, funcIndex)
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
	log.Printf("Extracted context for %s: %d functions in %v", filepath.Base(filePath), len(definitions), duration)
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

func lookupFunctionDefinition(language, funcName, filePath, repoPath string, funcIndex *FunctionIndex) (*FunctionDefinition, error) {
	var sig, body string
	var err error
	var found bool
	switch language {
	case "c":
		sig, body, err = TSFindCFunction(filePath, funcName)
	case "cpp":
		sig, body, err = TSFindCppMethod(filePath, funcName)
		if err != nil {
			sig, body, err = TSFindCppFunction(filePath, funcName)
		}
	case "csharp":
		sig, body, err = TSFindCSharpMethod(filePath, funcName)
	case "go":
		sig, body, err = TSFindGoFunction(filePath, funcName)
	case "java":
		sig, body, err = TSFindJavaMethod(filePath, funcName)
	case "javascript":
		sig, body, err = TSFindJSFunction(filePath, funcName)
	case "python":
		sig, body, err = TSFindPythonFunction(filePath, funcName)
	case "ruby":
		sig, body, err = TSFindRubyMethod(filePath, funcName)
	case "rust":
		sig, body, err = TSFindRustFunction(filePath, funcName)
	case "typescript":
		sig, body, err = TSFindTSFunction(filePath, funcName)
	case "php":
		sig, body, err = TSFindPHPMethod(filePath, funcName)
		if err != nil {
			sig, body, err = TSFindPHPFunction(filePath, funcName)
		}
	default:
		return nil, fmt.Errorf("unsupported language: %s", language)
	}
	if err == nil && sig != "" {
		return &FunctionDefinition{
			Name:      funcName,
			Language:  language,
			File:      filePath,
			Signature: sig,
			Body:      body,
		}, nil
	}
	if funcIndex != nil {
		candidatePaths := funcIndex.FindFunction(language, funcName)
		if len(candidatePaths) > 0 {
			for _, candidatePath := range candidatePaths {
				var candidateErr error
				switch language {
				case "c":
					sig, body, candidateErr = TSFindCFunction(candidatePath, funcName)
				case "cpp":
					sig, body, candidateErr = TSFindCppMethod(candidatePath, funcName)
					if candidateErr != nil {
						sig, body, candidateErr = TSFindCppFunction(candidatePath, funcName)
					}
				case "csharp":
					sig, body, candidateErr = TSFindCSharpMethod(candidatePath, funcName)
				case "go":
					sig, body, candidateErr = TSFindGoFunction(candidatePath, funcName)
				case "java":
					sig, body, candidateErr = TSFindJavaMethod(candidatePath, funcName)
				case "javascript":
					sig, body, candidateErr = TSFindJSFunction(candidatePath, funcName)
				case "python":
					sig, body, candidateErr = TSFindPythonFunction(candidatePath, funcName)
				case "ruby":
					sig, body, candidateErr = TSFindRubyMethod(candidatePath, funcName)
				case "rust":
					sig, body, candidateErr = TSFindRustFunction(candidatePath, funcName)
				case "typescript":
					sig, body, candidateErr = TSFindTSFunction(candidatePath, funcName)
				case "php":
					sig, body, candidateErr = TSFindPHPMethod(candidatePath, funcName)
					if candidateErr != nil {
						sig, body, candidateErr = TSFindPHPFunction(candidatePath, funcName)
					}
				}
				if candidateErr == nil && sig != "" {
					return &FunctionDefinition{
						Name:      funcName,
						Language:  language,
						File:      candidatePath,
						Signature: sig,
						Body:      body,
					}, nil
				}
			}
		}
	}
	if repoPath != "" {
		switch language {
		case "c":
			sig, body, found = scanCDefinitionInRepo(repoPath, funcName)
		case "cpp":
			sig, body, found = scanCppDefinitionInRepo(repoPath, funcName)
		case "csharp":
			sig, body, found = scanCSharpDefinitionInRepo(repoPath, funcName)
		case "go":
			sig, body, found = scanGoDefinitionInRepo(repoPath, funcName)
		case "java":
			sig, body, found = scanJavaDefinitionInRepo(repoPath, funcName)
		case "javascript":
			sig, body, found = scanJSDefinitionInRepo(repoPath, funcName)
		case "ruby":
			sig, body, found = scanRubyDefinitionInRepo(repoPath, funcName)
		case "rust":
			sig, body, found = scanRustDefinitionInRepo(repoPath, funcName)
		case "typescript":
			sig, body, found = scanTSDefinitionInRepo(repoPath, funcName)
		case "php":
			sig, body, found = scanPHPDefinitionInRepo(repoPath, funcName)
		}
		if found {
			return &FunctionDefinition{
				Name:      funcName,
				Language:  language,
				File:      repoPath,
				Signature: sig,
				Body:      body,
			}, nil
		}
	}
	return nil, fmt.Errorf("function %s not found in repository", funcName)
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
