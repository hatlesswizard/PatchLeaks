package main

import (
	"testing"
)

func TestBuiltinDetector_PHP(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"php builtin - array", "array", true},
		{"php builtin - strlen", "strlen", true},
		{"php builtin - json_encode", "json_encode", true},
		{"php builtin - mysqli_connect", "mysqli_connect", true},
		{"php builtin - exec", "exec", true},
		{"php user function", "myCustomFunction", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("php", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(php, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_JavaScript(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"js builtin - Array", "Array", true},
		{"js builtin - console.log", "log", true},
		{"js builtin - parseInt", "parseInt", true},
		{"js builtin - fetch", "fetch", true},
		{"js builtin - setTimeout", "setTimeout", true},
		{"js user function", "myCustomFunction", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("javascript", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(javascript, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_TypeScript(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"ts builtin - Promise", "Promise", true},
		{"ts builtin - Map", "Map", true},
		{"ts user function", "myCustomFunction", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("typescript", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(typescript, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_Python(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"python builtin - len", "len", true},
		{"python builtin - print", "print", true},
		{"python builtin - range", "range", true},
		{"python builtin - dict", "dict", true},
		{"python builtin - isinstance", "isinstance", true},
		{"python user function", "my_custom_function", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("python", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(python, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_C(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"c builtin - printf", "printf", true},
		{"c builtin - malloc", "malloc", true},
		{"c builtin - strcpy", "strcpy", true},
		{"c builtin - fopen", "fopen", true},
		{"c builtin - memcpy", "memcpy", true},
		{"c builtin - sin", "sin", true},
		{"c user function", "myFunction", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("c", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(c, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_Cpp(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"cpp builtin - cout", "cout", true},
		{"cpp builtin - vector", "vector", true},
		{"cpp builtin - push_back", "push_back", true},
		{"cpp builtin - sort", "sort", true},
		{"cpp builtin - make_shared", "make_shared", true},
		{"cpp user function", "myFunction", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("cpp", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(cpp, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_CSharp(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"csharp builtin - WriteLine", "WriteLine", true},
		{"csharp builtin - ToString", "ToString", true},
		{"csharp builtin - Add", "Add", true},
		{"csharp builtin - Where", "Where", true},
		{"csharp builtin - Select", "Select", true},
		{"csharp user function", "MyCustomMethod", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("csharp", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(csharp, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_Go(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"go builtin - len", "len", true},
		{"go builtin - make", "make", true},
		{"go builtin - append", "append", true},
		{"go builtin - panic", "panic", true},
		{"go builtin - close", "close", true},
		{"go user function", "myFunction", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("go", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(go, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_Java(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"java builtin - println", "println", true},
		{"java builtin - toString", "toString", true},
		{"java builtin - equals", "equals", true},
		{"java builtin - parseInt", "parseInt", true},
		{"java builtin - sort", "sort", true},
		{"java user function", "myMethod", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("java", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(java, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_Ruby(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"ruby builtin - puts", "puts", true},
		{"ruby builtin - print", "print", true},
		{"ruby builtin - each", "each", true},
		{"ruby builtin - map", "map", true},
		{"ruby builtin - require", "require", true},
		{"ruby user function", "my_method", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("ruby", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(ruby, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_Rust(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		funcName string
		want     bool
	}{
		{"rust builtin - println!", "println!", true},
		{"rust builtin - println", "println", true},
		{"rust builtin - vec!", "vec!", true},
		{"rust builtin - panic!", "panic!", true},
		{"rust builtin - unwrap", "unwrap", true},
		{"rust builtin - collect", "collect", true},
		{"rust user function", "my_function", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin("rust", tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(rust, %q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_UnknownLanguage(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		language string
		funcName string
		want     bool
	}{
		{"unknown language", "cobol", "DISPLAY", false},
		{"empty language", "", "func", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin(tt.language, tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(%q, %q) = %v, want %v", tt.language, tt.funcName, got, tt.want)
			}
		})
	}
}

func TestBuiltinDetector_InitializationOnce(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	if len(bd.phpBuiltins) == 0 {
		t.Error("PHP builtins not loaded")
	}
	if len(bd.jsBuiltins) == 0 {
		t.Error("JavaScript builtins not loaded")
	}
	if len(bd.pyBuiltins) == 0 {
		t.Error("Python builtins not loaded")
	}
	if len(bd.cBuiltins) == 0 {
		t.Error("C builtins not loaded")
	}
	if len(bd.cppBuiltins) == 0 {
		t.Error("C++ builtins not loaded")
	}
	if len(bd.csharpBuiltins) == 0 {
		t.Error("C# builtins not loaded")
	}
	if len(bd.goBuiltins) == 0 {
		t.Error("Go builtins not loaded")
	}
	if len(bd.javaBuiltins) == 0 {
		t.Error("Java builtins not loaded")
	}
	if len(bd.rubyBuiltins) == 0 {
		t.Error("Ruby builtins not loaded")
	}
	if len(bd.rustBuiltins) == 0 {
		t.Error("Rust builtins not loaded")
	}
	bd.initialize()
	if !bd.initialized {
		t.Error("Detector should be marked as initialized")
	}
}

func TestGetBuiltinDetector_Singleton(t *testing.T) {
	bd1 := GetBuiltinDetector()
	bd2 := GetBuiltinDetector()
	if bd1 != bd2 {
		t.Error("GetBuiltinDetector should return the same instance (singleton)")
	}
}

func TestBuiltinDetector_SpecialCharacters(t *testing.T) {
	bd := NewBuiltinDetector()
	bd.initialize()
	tests := []struct {
		name     string
		language string
		funcName string
		want     bool
	}{
		{"rust macro with !", "rust", "println!", true},
		{"ruby method with ?", "ruby", "nil?", true},
		{"function with _", "python", "__import__", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bd.IsBuiltin(tt.language, tt.funcName); got != tt.want {
				t.Errorf("IsBuiltin(%q, %q) = %v, want %v", tt.language, tt.funcName, got, tt.want)
			}
		})
	}
}
