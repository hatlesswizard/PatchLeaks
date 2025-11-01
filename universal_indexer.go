package main

import (
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strings"
)

// FunctionDefinition represents a function or method definition in any supported language
type FunctionDefinition struct {
	Name      string `json:"name"`
	Language  string `json:"language"`
	File      string `json:"file"`
	Signature string `json:"signature"`
	Body      string `json:"body"`
	IsMethod  bool   `json:"is_method"`
	ClassName string `json:"class_name,omitempty"` // for methods
}

// DetectLanguage detects the programming language from file extension
func DetectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	
	switch ext {
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".h++":
		return "cpp"
	case ".cs":
		return "csharp"
	case ".go":
		return "go"
	case ".java":
		return "java"
	case ".js", ".jsx", ".mjs":
		return "javascript"
	case ".php":
		return "php"
	case ".py":
		return "python"
	case ".rb":
		return "ruby"
	case ".rs":
		return "rust"
	case ".ts", ".tsx":
		return "typescript"
	default:
		return "unknown"
	}
}

// ExtractFunctionContext extracts function context from a file for AI analysis
// It automatically detects the language, finds function calls, and resolves their definitions
func ExtractFunctionContext(filePath, diffContent string, includeContext bool) (string, error) {
	if !includeContext {
		return "", nil
	}
	
	// Detect language
	language := DetectLanguage(filePath)
	if language == "unknown" {
		log.Printf("Unknown language for file: %s, skipping context extraction", filePath)
		return "", nil
	}
	
	// Extract function names from diff
	functionCalls := extractFunctionCallsFromDiff(diffContent, language)
	if len(functionCalls) == 0 {
		log.Printf("No function calls found in diff for %s", filePath)
		return "", nil
	}
	
	// Get definitions for each function call
	definitions := make([]FunctionDefinition, 0)
	repoPath := filepath.Dir(filePath)
	
	for _, funcName := range functionCalls {
		def, err := lookupFunctionDefinition(language, funcName, filePath, repoPath)
		if err != nil {
			log.Printf("Could not find definition for %s.%s: %v", language, funcName, err)
			continue
		}
		if def != nil {
			definitions = append(definitions, *def)
		}
	}
	
	if len(definitions) == 0 {
		return "", nil
	}
	
	// Format context for AI
	context := formatFunctionContext(definitions)
	return context, nil
}

// extractFunctionCallsFromDiff extracts function/method call names from diff content
func extractFunctionCallsFromDiff(diffContent, language string) []string {
	var calls []string
	seen := make(map[string]bool)
	
	// Language-specific patterns
	var patterns []*regexp.Regexp
	
	switch language {
	case "c", "cpp", "go", "rust":
		// function_name(
		patterns = append(patterns, regexp.MustCompile(`\b([a-z_][a-z0-9_]*)\s*\(`))
	case "java", "csharp":
		// method calls: object.method( or this.method( or ClassName.method(
		patterns = append(patterns, regexp.MustCompile(`(?:this|[a-z][a-zA-Z0-9_]*)\s*\.\s*([a-z][a-zA-Z0-9_]*)\s*\(`))
		// standalone: methodName(
		patterns = append(patterns, regexp.MustCompile(`\b([a-z][a-z0-9_]*)\s*\(`))
	case "javascript", "typescript":
		// method calls: object.method( or this.method(
		patterns = append(patterns, regexp.MustCompile(`(?:this|[a-z][a-zA-Z0-9_]*)\s*\.\s*([a-z][a-zA-Z0-9_]*)\s*\(`))
		// standalone: functionName(
		patterns = append(patterns, regexp.MustCompile(`\b([a-z][a-zA-Z0-9_]*)\s*\(`))
	case "python":
		// function calls: function_name(
		patterns = append(patterns, regexp.MustCompile(`\b([a-z_][a-z0-9_]*)\s*\(`))
		// method calls: object.method(
		patterns = append(patterns, regexp.MustCompile(`(?:self|[a-z_][a-z0-9_]*)\s*\.\s*([a-z_][a-z0-9_]*)\s*\(`))
	case "ruby":
		// method calls: object.method or method(
		patterns = append(patterns, regexp.MustCompile(`(?:[a-z_][a-z0-9_]*)\s*\.\s*([a-z_][a-z0-9_]*)`))
		patterns = append(patterns, regexp.MustCompile(`\b([a-z_][a-z0-9_]*)\s*\(`))
	case "php":
		// $this->method(
		patterns = append(patterns, regexp.MustCompile(`\$this\s*->\s*([a-z_][a-zA-Z0-9_]*)\s*\(`))
		// ClassName::method(
		patterns = append(patterns, regexp.MustCompile(`(?:[A-Z][a-zA-Z0-9_]*)::\s*([a-z_][a-zA-Z0-9_]*)\s*\(`))
		// function_name(
		patterns = append(patterns, regexp.MustCompile(`\b([a-z_][a-z0-9_]*)\s*\(`))
	}
	
	// Extract calls using patterns
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(diffContent, -1)
		for _, match := range matches {
			if len(match) > 1 {
				funcName := match[1]
				// Filter out common built-ins and keywords
				if !isBuiltinOrKeyword(funcName, language) && !seen[funcName] {
					calls = append(calls, funcName)
					seen[funcName] = true
				}
			}
		}
	}
	
	return calls
}

// isBuiltinOrKeyword checks if a name is a built-in function or keyword
func isBuiltinOrKeyword(name, language string) bool {
	builtins := map[string]map[string]bool{
		"c": {"printf": true, "scanf": true, "malloc": true, "free": true, "sizeof": true, "if": true, "for": true, "while": true},
		"cpp": {"cout": true, "cin": true, "endl": true, "printf": true, "scanf": true, "if": true, "for": true, "while": true},
		"go": {"println": true, "print": true, "len": true, "make": true, "append": true, "if": true, "for": true, "range": true},
		"java": {"println": true, "print": true, "length": true, "if": true, "for": true, "while": true},
		"javascript": {"console": true, "log": true, "length": true, "if": true, "for": true, "while": true},
		"python": {"print": true, "len": true, "range": true, "str": true, "int": true, "if": true, "for": true, "while": true},
		"ruby": {"puts": true, "print": true, "length": true, "if": true, "for": true, "while": true},
		"rust": {"println": true, "print": true, "len": true, "if": true, "for": true, "while": true},
		"typescript": {"console": true, "log": true, "length": true, "if": true, "for": true, "while": true},
		"php": {"echo": true, "print": true, "var_dump": true, "count": true, "if": true, "for": true, "while": true},
	}
	
	if langBuiltins, ok := builtins[language]; ok {
		return langBuiltins[name]
	}
	return false
}

// lookupFunctionDefinition looks up a function definition using tree-sitter
func lookupFunctionDefinition(language, funcName, filePath, repoPath string) (*FunctionDefinition, error) {
	var sig, body string
	var err error
	var found bool
	
	// Try to find in the same file first, then cross-file
	switch language {
	case "c":
		sig, body, err = TSFindCFunction(filePath, funcName)
		if err != nil {
			// Try cross-file
			sig, body, found = scanCDefinitionInRepo(repoPath, funcName)
			if !found {
				return nil, fmt.Errorf("function not found")
			}
		}
	case "cpp":
		// Try as method first
		sig, body, err = TSFindCppMethod(filePath, funcName)
		if err != nil {
			// Try as function
			sig, body, err = TSFindCppFunction(filePath, funcName)
			if err != nil {
				// Try cross-file
				sig, body, found = scanCppDefinitionInRepo(repoPath, funcName)
				if !found {
					return nil, fmt.Errorf("function not found")
				}
			}
		}
	case "csharp":
		sig, body, err = TSFindCSharpMethod(filePath, funcName)
		if err != nil {
			sig, body, found = scanCSharpDefinitionInRepo(repoPath, funcName)
			if !found {
				return nil, fmt.Errorf("method not found")
			}
		}
	case "go":
		sig, body, err = TSFindGoFunction(filePath, funcName)
		if err != nil {
			sig, body, found = scanGoDefinitionInRepo(repoPath, funcName)
			if !found {
				return nil, fmt.Errorf("function not found")
			}
		}
	case "java":
		sig, body, err = TSFindJavaMethod(filePath, funcName)
		if err != nil {
			sig, body, found = scanJavaDefinitionInRepo(repoPath, funcName)
			if !found {
				return nil, fmt.Errorf("method not found")
			}
		}
	case "javascript":
		sig, body, err = TSFindJSFunction(filePath, funcName)
		if err != nil {
			sig, body, found = scanJSDefinitionInRepo(repoPath, funcName)
			if !found {
				return nil, fmt.Errorf("function not found")
			}
		}
	case "python":
		sig, body, err = TSFindPythonFunction(filePath, funcName)
		if err != nil {
			return nil, fmt.Errorf("function not found")
		}
	case "ruby":
		sig, body, err = TSFindRubyMethod(filePath, funcName)
		if err != nil {
			sig, body, found = scanRubyDefinitionInRepo(repoPath, funcName)
			if !found {
				return nil, fmt.Errorf("method not found")
			}
		}
	case "rust":
		sig, body, err = TSFindRustFunction(filePath, funcName)
		if err != nil {
			sig, body, found = scanRustDefinitionInRepo(repoPath, funcName)
			if !found {
				return nil, fmt.Errorf("function not found")
			}
		}
	case "typescript":
		sig, body, err = TSFindTSFunction(filePath, funcName)
		if err != nil {
			sig, body, found = scanTSDefinitionInRepo(repoPath, funcName)
			if !found {
				return nil, fmt.Errorf("function not found")
			}
		}
	case "php":
		// Try as method first
		sig, body, err = TSFindPHPMethod(filePath, funcName)
		if err != nil {
			// Try as function
			sig, body, err = TSFindPHPFunction(filePath, funcName)
			if err != nil {
				// Try cross-file
				sig, body, found = scanPHPDefinitionInRepo(repoPath, funcName)
				if !found {
					return nil, fmt.Errorf("function not found")
				}
			}
		}
	default:
		return nil, fmt.Errorf("unsupported language: %s", language)
	}
	
	return &FunctionDefinition{
		Name:      funcName,
		Language:  language,
		File:      filePath,
		Signature: sig,
		Body:      body,
	}, nil
}

// formatFunctionContext formats function definitions for AI prompt
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
		
		// Include full signature and body
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

