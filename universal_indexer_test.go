package main

import (
	"testing"
)

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{"c file .c", "test.c", "c"},
		{"c file .h", "header.h", "c"},
		{"c file uppercase", "TEST.C", "c"},
		{"cpp file .cpp", "test.cpp", "cpp"},
		{"cpp file .cc", "test.cc", "cpp"},
		{"cpp file .cxx", "test.cxx", "cpp"},
		{"cpp file .hpp", "test.hpp", "cpp"},
		{"cpp file .hxx", "test.hxx", "cpp"},
		{"cpp file .h++", "test.h++", "cpp"},
		{"cpp file .c++", "test.c++", "cpp"},
		{"cpp file .hh", "test.hh", "cpp"},
		{"cpp file .ii", "test.ii", "cpp"},
		{"cpp file .ixx", "test.ixx", "cpp"},
		{"csharp file .cs", "Program.cs", "csharp"},
		{"csharp file .csx", "script.csx", "csharp"},
		{"csharp file uppercase", "PROGRAM.CS", "csharp"},
		{"go file .go", "main.go", "go"},
		{"go file uppercase", "MAIN.GO", "go"},
		{"java file .java", "Main.java", "java"},
		{"java file uppercase", "MAIN.JAVA", "java"},
		{"js file .js", "app.js", "javascript"},
		{"js file .jsx", "component.jsx", "javascript"},
		{"js file .mjs", "module.mjs", "javascript"},
		{"js file .cjs", "common.cjs", "javascript"},
		{"js file uppercase", "APP.JS", "javascript"},
		{"php file .php", "index.php", "php"},
		{"php file .phtml", "template.phtml", "php"},
		{"php file .php3", "old.php3", "php"},
		{"php file .php4", "legacy.php4", "php"},
		{"php file .php5", "site.php5", "php"},
		{"php file .phps", "source.phps", "php"},
		{"php file uppercase", "INDEX.PHP", "php"},
		{"python file .py", "script.py", "python"},
		{"python file .pyw", "gui.pyw", "python"},
		{"python file .pyi", "stubs.pyi", "python"},
		{"python file .pyx", "cython.pyx", "python"},
		{"python file uppercase", "SCRIPT.PY", "python"},
		{"ruby file .rb", "app.rb", "ruby"},
		{"ruby file .rake", "Rakefile.rake", "ruby"},
		{"ruby file .gemspec", "mygem.gemspec", "ruby"},
		{"ruby file .ru", "config.ru", "ruby"},
		{"ruby file uppercase", "APP.RB", "ruby"},
		{"rust file .rs", "main.rs", "rust"},
		{"rust file .rlib", "lib.rlib", "rust"},
		{"rust file uppercase", "MAIN.RS", "rust"},
		{"ts file .ts", "app.ts", "typescript"},
		{"ts file .tsx", "component.tsx", "typescript"},
		{"ts file .mts", "module.mts", "typescript"},
		{"ts file .cts", "common.cts", "typescript"},
		{"ts file uppercase", "APP.TS", "typescript"},
		{"unknown file .txt", "readme.txt", "unknown"},
		{"unknown file .md", "README.md", "unknown"},
		{"unknown file .json", "config.json", "unknown"},
		{"no extension", "Makefile", "unknown"},
		{"empty string", "", "unknown"},
		{"weird extension", "file.xyz123", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectLanguage(tt.filePath); got != tt.want {
				t.Errorf("DetectLanguage(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestDetectLanguage_PathsWithDirectories(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{"nested c file", "src/main.c", "c"},
		{"nested js file", "src/components/App.jsx", "javascript"},
		{"nested php file", "public/index.php", "php"},
		{"absolute path", "/usr/local/bin/script.py", "python"},
		{"windows path", "C:\\Users\\test\\file.cs", "csharp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectLanguage(tt.filePath); got != tt.want {
				t.Errorf("DetectLanguage(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestDetectLanguage_CaseInsensitivity(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{"lowercase", "test.cpp", "cpp"},
		{"uppercase", "TEST.CPP", "cpp"},
		{"mixed case", "TeSt.CpP", "cpp"},
		{"lowercase php", "index.php", "php"},
		{"uppercase php", "INDEX.PHP", "php"},
		{"mixed case php", "InDeX.PhP", "php"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectLanguage(tt.filePath); got != tt.want {
				t.Errorf("DetectLanguage(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}

func TestDetectLanguage_AllExtensionsUnique(t *testing.T) {
	testCases := map[string]string{
		".c":       "c",
		".cpp":     "cpp",
		".cs":      "csharp",
		".go":      "go",
		".java":    "java",
		".js":      "javascript",
		".php":     "php",
		".py":      "python",
		".rb":      "ruby",
		".rs":      "rust",
		".ts":      "typescript",
		".phtml":   "php",
		".pyx":     "python",
		".rake":    "ruby",
		".tsx":     "typescript",
		".mjs":     "javascript",
		".cjs":     "javascript",
		".mts":     "typescript",
		".cts":     "typescript",
		".csx":     "csharp",
		".rlib":    "rust",
		".gemspec": "ruby",
		".ru":      "ruby",
		".pyw":     "python",
		".pyi":     "python",
		".phps":    "php",
		".php3":    "php",
		".php4":    "php",
		".php5":    "php",
		".ixx":     "cpp",
		".ii":      "cpp",
		".hh":      "cpp",
		".c++":     "cpp",
		".h++":     "cpp",
	}
	for ext, expectedLang := range testCases {
		t.Run("extension "+ext, func(t *testing.T) {
			filename := "test" + ext
			if got := DetectLanguage(filename); got != expectedLang {
				t.Errorf("DetectLanguage(%q) = %v, want %v", filename, got, expectedLang)
			}
		})
	}
}

func TestDetectLanguage_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
	}{
		{"multiple dots", "test.min.js", "javascript"},
		{"hidden file", ".config.py", "python"},
		{"no basename", ".php", "php"},
		{"dot at start", ".rs", "rust"},
		{"special chars in name", "test-file_v2.cpp", "cpp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectLanguage(tt.filePath); got != tt.want {
				t.Errorf("DetectLanguage(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}
