package main

import (
	"encoding/json"
	"log"
	"os/exec"
	"strings"
	"sync"
)

type BuiltinDetector struct {
	phpBuiltins    map[string]bool
	jsBuiltins     map[string]bool
	pyBuiltins     map[string]bool
	cBuiltins      map[string]bool
	cppBuiltins    map[string]bool
	csharpBuiltins map[string]bool
	goBuiltins     map[string]bool
	javaBuiltins   map[string]bool
	rubyBuiltins   map[string]bool
	rustBuiltins   map[string]bool
	mu             sync.RWMutex
	initialized    bool
}

var (
	globalBuiltinDetector *BuiltinDetector
	detectorOnce          sync.Once
)

func GetBuiltinDetector() *BuiltinDetector {
	detectorOnce.Do(func() {
		globalBuiltinDetector = NewBuiltinDetector()
	})
	return globalBuiltinDetector
}

func NewBuiltinDetector() *BuiltinDetector {
	bd := &BuiltinDetector{
		phpBuiltins:    make(map[string]bool),
		jsBuiltins:     make(map[string]bool),
		pyBuiltins:     make(map[string]bool),
		cBuiltins:      make(map[string]bool),
		cppBuiltins:    make(map[string]bool),
		csharpBuiltins: make(map[string]bool),
		goBuiltins:     make(map[string]bool),
		javaBuiltins:   make(map[string]bool),
		rubyBuiltins:   make(map[string]bool),
		rustBuiltins:   make(map[string]bool),
		initialized:    false,
	}
	go bd.initialize()
	return bd
}

func (bd *BuiltinDetector) initialize() {
	bd.mu.Lock()
	defer bd.mu.Unlock()
	if bd.initialized {
		return
	}
	log.Printf("Initializing built-in function detector...")
	bd.loadPHPBuiltins()
	bd.loadJavaScriptBuiltins()
	bd.loadPythonBuiltins()
	bd.loadCBuiltins()
	bd.loadCppBuiltins()
	bd.loadCSharpBuiltins()
	bd.loadGoBuiltins()
	bd.loadJavaBuiltins()
	bd.loadRubyBuiltins()
	bd.loadRustBuiltins()
	bd.initialized = true
	total := len(bd.phpBuiltins) + len(bd.jsBuiltins) + len(bd.pyBuiltins) +
		len(bd.cBuiltins) + len(bd.cppBuiltins) + len(bd.csharpBuiltins) +
		len(bd.goBuiltins) + len(bd.javaBuiltins) + len(bd.rubyBuiltins) +
		len(bd.rustBuiltins)
	log.Printf("Built-in detector initialized: %d PHP, %d JS, %d Python, %d C, %d C++, %d C#, %d Go, %d Java, %d Ruby, %d Rust functions",
		len(bd.phpBuiltins), len(bd.jsBuiltins), len(bd.pyBuiltins), len(bd.cBuiltins),
		len(bd.cppBuiltins), len(bd.csharpBuiltins), len(bd.goBuiltins), len(bd.javaBuiltins),
		len(bd.rubyBuiltins), len(bd.rustBuiltins))
	log.Printf("Total built-in functions: %d", total)
}

func (bd *BuiltinDetector) IsBuiltin(language, funcName string) bool {
	if !bd.initialized {
		bd.initialize()
	}
	bd.mu.RLock()
	defer bd.mu.RUnlock()
	switch language {
	case "php":
		return bd.phpBuiltins[funcName]
	case "javascript", "typescript":
		return bd.jsBuiltins[funcName]
	case "python":
		return bd.pyBuiltins[funcName]
	case "c":
		return bd.cBuiltins[funcName]
	case "cpp":
		return bd.cppBuiltins[funcName]
	case "csharp":
		return bd.csharpBuiltins[funcName]
	case "go":
		return bd.goBuiltins[funcName]
	case "java":
		return bd.javaBuiltins[funcName]
	case "ruby":
		return bd.rubyBuiltins[funcName]
	case "rust":
		return bd.rustBuiltins[funcName]
	default:
		return false
	}
}

func (bd *BuiltinDetector) loadPHPBuiltins() {
	languageConstructs := []string{
		"array", "list", "echo", "print", "die", "exit", "empty", "isset", "unset",
		"eval", "include", "include_once", "require", "require_once",
	}
	for _, f := range languageConstructs {
		bd.phpBuiltins[f] = true
	}
	cmd := exec.Command("php", "-r", "echo json_encode(get_defined_functions()['internal']);")
	output, err := cmd.Output()
	if err == nil {
		var funcs []string
		if json.Unmarshal(output, &funcs) == nil {
			for _, f := range funcs {
				bd.phpBuiltins[f] = true
			}
			log.Printf("Loaded %d PHP built-in functions from PHP CLI (+ %d language constructs)", len(funcs), len(languageConstructs))
			return
		}
	}
	commonPHPBuiltins := []string{
		"array_key_exists", "array_merge", "array_push", "array_search",
		"count", "explode", "file_get_contents", "file_put_contents",
		"htmlspecialchars", "htmlentities", "implode", "in_array",
		"json_decode", "json_encode", "md5", "preg_match", "preg_replace",
		"sha1", "strlen", "strpos", "str_replace", "substr", "trim",
		"urlencode", "urldecode", "var_dump", "print_r",
		"mysql_connect", "mysqli_connect", "pg_connect", "sqlite_open",
		"exec", "system", "shell_exec", "passthru", "assert",
		"base64_encode", "base64_decode", "serialize", "unserialize",
		"get_defined_functions", "function_exists", "class_exists",
		"method_exists", "property_exists", "defined", "constant",
	}
	for _, f := range commonPHPBuiltins {
		bd.phpBuiltins[f] = true
	}
	log.Printf("Loaded %d PHP built-in functions from fallback list (+ %d language constructs)", len(commonPHPBuiltins), len(languageConstructs))
}

func (bd *BuiltinDetector) loadJavaScriptBuiltins() {
	jsBuiltins := []string{
		"Array", "Object", "String", "Number", "Boolean", "Date", "RegExp",
		"Math", "JSON", "Promise", "Set", "Map", "WeakSet", "WeakMap",
		"Symbol", "BigInt", "Proxy", "Reflect",
		"push", "pop", "shift", "unshift", "slice", "splice", "concat",
		"join", "reverse", "sort", "indexOf", "lastIndexOf", "includes",
		"find", "findIndex", "filter", "map", "reduce", "forEach", "some", "every",
		"charAt", "charCodeAt", "concat", "indexOf", "lastIndexOf", "match",
		"replace", "search", "slice", "split", "substring", "substr", "toLowerCase",
		"toUpperCase", "trim", "trimStart", "trimEnd", "startsWith", "endsWith",
		"keys", "values", "entries", "assign", "create", "defineProperty",
		"freeze", "seal", "isFrozen", "isSealed",
		"abs", "ceil", "floor", "round", "max", "min", "random", "sqrt", "pow",
		"parse", "stringify",
		"log", "error", "warn", "info", "debug", "trace",
		"parseInt", "parseFloat", "isNaN", "isFinite", "encodeURI", "decodeURI",
		"encodeURIComponent", "decodeURIComponent", "eval", "setTimeout", "setInterval",
		"clearTimeout", "clearInterval",
		"require", "module", "exports", "process", "Buffer", "global",
		"fetch", "XMLHttpRequest", "localStorage", "sessionStorage", "document",
		"window", "navigator", "location", "history",
	}
	for _, f := range jsBuiltins {
		bd.jsBuiltins[f] = true
	}
	log.Printf("Loaded %d JavaScript built-in functions", len(jsBuiltins))
}

func (bd *BuiltinDetector) loadPythonBuiltins() {
	cmd := exec.Command("python3", "-c", "import json; import builtins; print(json.dumps([x for x in dir(builtins) if callable(getattr(builtins, x, None)) or x in ['__import__', '__build_class__']]))")
	output, err := cmd.Output()
	if err == nil {
		var funcs []string
		if json.Unmarshal(output, &funcs) == nil {
			for _, f := range funcs {
				bd.pyBuiltins[f] = true
			}
			log.Printf("Loaded %d Python built-in functions from Python CLI", len(funcs))
			return
		}
	}
	cmd = exec.Command("python", "-c", "import json; import builtins; print(json.dumps([x for x in dir(builtins) if callable(getattr(builtins, x, None)) or x in ['__import__', '__build_class__']]))")
	output, err = cmd.Output()
	if err == nil {
		var funcs []string
		if json.Unmarshal(output, &funcs) == nil {
			for _, f := range funcs {
				bd.pyBuiltins[f] = true
			}
			log.Printf("Loaded %d Python built-in functions from Python CLI", len(funcs))
			return
		}
	}
	commonPythonBuiltins := []string{
		"abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes",
		"callable", "chr", "classmethod", "compile", "complex", "delattr",
		"dict", "dir", "divmod", "enumerate", "eval", "exec", "filter",
		"float", "format", "frozenset", "getattr", "globals", "hasattr",
		"hash", "help", "hex", "id", "input", "int", "isinstance", "issubclass",
		"iter", "len", "list", "locals", "map", "max", "memoryview", "min",
		"next", "object", "oct", "open", "ord", "pow", "print", "property",
		"range", "repr", "reversed", "round", "set", "setattr", "slice",
		"sorted", "staticmethod", "str", "sum", "super", "tuple", "type",
		"vars", "zip", "__import__",
	}
	for _, f := range commonPythonBuiltins {
		bd.pyBuiltins[f] = true
	}
	log.Printf("Loaded %d Python built-in functions from fallback list", len(commonPythonBuiltins))
}

func (bd *BuiltinDetector) loadCBuiltins() {
	cBuiltins := []string{
		"printf", "fprintf", "sprintf", "snprintf", "scanf", "fscanf", "sscanf",
		"fopen", "fclose", "fread", "fwrite", "fgets", "fputs", "fgetc", "fputc",
		"getchar", "putchar", "gets", "puts", "fseek", "ftell", "rewind", "feof",
		"ferror", "clearerr", "perror", "remove", "rename", "tmpfile", "tmpnam",
		"setvbuf", "setbuf", "fflush", "freopen", "ungetc",
		"malloc", "calloc", "realloc", "free", "exit", "abort", "atexit",
		"atoi", "atof", "atol", "strtol", "strtod", "strtoul", "rand", "srand",
		"abs", "labs", "div", "ldiv", "qsort", "bsearch", "system", "getenv",
		"mblen", "mbtowc", "wctomb", "mbstowcs", "wcstombs",
		"strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp", "strchr",
		"strrchr", "strstr", "strlen", "strspn", "strcspn", "strpbrk", "strtok",
		"memcpy", "memmove", "memcmp", "memchr", "memset", "strerror",
		"sin", "cos", "tan", "asin", "acos", "atan", "atan2", "sinh", "cosh",
		"tanh", "exp", "log", "log10", "pow", "sqrt", "ceil", "floor", "fabs",
		"fmod", "frexp", "ldexp", "modf",
		"time", "difftime", "mktime", "asctime", "ctime", "gmtime", "localtime",
		"strftime", "clock",
		"isalnum", "isalpha", "isdigit", "isxdigit", "islower", "isupper",
		"isspace", "iscntrl", "ispunct", "isprint", "isgraph", "tolower", "toupper",
		"assert",
		"signal", "raise",
		"setjmp", "longjmp",
		"va_start", "va_arg", "va_end", "va_copy",
	}
	for _, f := range cBuiltins {
		bd.cBuiltins[f] = true
	}
	log.Printf("Loaded %d C standard library functions", len(cBuiltins))
}

func (bd *BuiltinDetector) loadCppBuiltins() {
	cppBuiltins := []string{
		"cout", "cin", "cerr", "clog", "endl", "flush",
		"string", "append", "substr", "find", "rfind", "replace", "erase",
		"insert", "c_str", "length", "size", "empty", "clear", "at",
		"vector", "push_back", "pop_back", "emplace_back", "begin", "end",
		"rbegin", "rend", "front", "back", "resize", "reserve", "capacity",
		"sort", "reverse", "find", "find_if", "count", "count_if", "accumulate",
		"for_each", "transform", "remove", "remove_if", "unique", "binary_search",
		"lower_bound", "upper_bound", "min", "max", "swap", "fill", "copy",
		"move", "replace", "replace_if", "merge", "partition", "rotate",
		"map", "insert", "erase", "find", "count", "lower_bound", "upper_bound",
		"set", "insert", "erase", "find", "count",
		"list", "push_front", "pop_front", "push_back", "pop_back",
		"queue", "push", "pop", "front", "back",
		"stack", "push", "pop", "top",
		"priority_queue", "push", "pop", "top",
		"pair", "make_pair", "first", "second",
		"move", "forward", "swap",
		"make_shared", "make_unique", "shared_ptr", "unique_ptr", "weak_ptr",
		"printf", "malloc", "free", "memcpy", "strlen", "strcpy", "strcmp",
	}
	for _, f := range cppBuiltins {
		bd.cppBuiltins[f] = true
	}
	log.Printf("Loaded %d C++ standard library functions", len(cppBuiltins))
}

func (bd *BuiltinDetector) loadCSharpBuiltins() {
	csharpBuiltins := []string{
		"WriteLine", "Write", "ReadLine", "Read", "Clear",
		"ToString", "Format", "Concat", "Join", "Split", "Substring", "Replace",
		"IndexOf", "LastIndexOf", "StartsWith", "EndsWith", "ToLower", "ToUpper",
		"Trim", "TrimStart", "TrimEnd", "PadLeft", "PadRight", "Contains",
		"Remove", "Insert", "IsNullOrEmpty", "IsNullOrWhiteSpace",
		"Sort", "Reverse", "IndexOf", "LastIndexOf", "Find", "FindAll",
		"Exists", "ForEach", "Clear", "Copy", "Resize",
		"Add", "Remove", "RemoveAt", "Clear", "Contains", "IndexOf", "Insert",
		"Count", "Sort", "Reverse", "Find", "FindAll", "Exists", "ForEach",
		"Add", "Remove", "ContainsKey", "ContainsValue", "TryGetValue", "Clear",
		"Abs", "Ceiling", "Floor", "Round", "Max", "Min", "Sqrt", "Pow",
		"Sin", "Cos", "Tan", "Log", "Log10", "Exp",
		"ToInt32", "ToDouble", "ToBoolean", "ToString", "ToDateTime",
		"Now", "Today", "Parse", "TryParse", "AddDays", "AddMonths", "AddYears",
		"Exists", "ReadAllText", "WriteAllText", "ReadAllLines", "WriteAllLines",
		"Copy", "Move", "Delete", "Create", "Open",
		"Exists", "Create", "Delete", "GetFiles", "GetDirectories", "Move",
		"Select", "Where", "OrderBy", "OrderByDescending", "GroupBy", "Join",
		"First", "FirstOrDefault", "Last", "LastOrDefault", "Single", "Any",
		"All", "Count", "Sum", "Average", "Max", "Min", "Take", "Skip",
		"Distinct", "Union", "Intersect", "Except",
		"GetType", "GetHashCode", "Equals", "ReferenceEquals",
	}
	for _, f := range csharpBuiltins {
		bd.csharpBuiltins[f] = true
	}
	log.Printf("Loaded %d C# .NET built-in methods", len(csharpBuiltins))
}

func (bd *BuiltinDetector) loadGoBuiltins() {
	cmd := exec.Command("go", "doc", "builtin")
	output, err := cmd.Output()
	if err == nil {
		_ = output
	}
	goBuiltins := []string{
		"append", "cap", "close", "complex", "copy", "delete", "imag",
		"len", "make", "new", "panic", "print", "println", "real", "recover",
		"bool", "byte", "complex64", "complex128", "error", "float32", "float64",
		"int", "int8", "int16", "int32", "int64", "rune", "string",
		"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
	}
	for _, f := range goBuiltins {
		bd.goBuiltins[f] = true
	}
	log.Printf("Loaded %d Go built-in functions", len(goBuiltins))
}

func (bd *BuiltinDetector) loadJavaBuiltins() {
	javaBuiltins := []string{
		"println", "print", "printf", "currentTimeMillis", "nanoTime",
		"arraycopy", "exit", "gc", "getProperty", "getenv",
		"length", "charAt", "substring", "indexOf", "lastIndexOf", "startsWith",
		"endsWith", "equals", "equalsIgnoreCase", "compareTo", "compareToIgnoreCase",
		"toLowerCase", "toUpperCase", "trim", "replace", "replaceAll", "split",
		"contains", "isEmpty", "concat", "format", "valueOf", "matches",
		"append", "insert", "delete", "replace", "reverse", "toString",
		"abs", "ceil", "floor", "round", "max", "min", "sqrt", "pow", "exp",
		"log", "log10", "sin", "cos", "tan", "asin", "acos", "atan", "random",
		"toString", "equals", "hashCode", "getClass", "clone", "notify",
		"notifyAll", "wait",
		"sort", "binarySearch", "fill", "copyOf", "copyOfRange", "asList",
		"equals", "deepEquals", "toString", "deepToString",
		"sort", "reverse", "shuffle", "min", "max", "binarySearch", "fill",
		"copy", "swap", "addAll", "frequency",
		"parseInt", "parseDouble", "parseFloat", "parseLong", "valueOf",
		"sleep", "yield", "currentThread", "start", "run", "join",
	}
	for _, f := range javaBuiltins {
		bd.javaBuiltins[f] = true
	}
	log.Printf("Loaded %d Java built-in methods", len(javaBuiltins))
}

func (bd *BuiltinDetector) loadRubyBuiltins() {
	cmd := exec.Command("ruby", "-e", "puts (Kernel.methods + Object.instance_methods + Array.instance_methods + Hash.instance_methods).uniq.sort")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			method := strings.TrimSpace(line)
			if method != "" {
				bd.rubyBuiltins[method] = true
			}
		}
		if len(bd.rubyBuiltins) > 0 {
			log.Printf("Loaded %d Ruby built-in methods from Ruby CLI", len(bd.rubyBuiltins))
			return
		}
	}
	rubyBuiltins := []string{
		"puts", "print", "p", "printf", "gets", "readline", "readlines",
		"require", "require_relative", "load", "raise", "fail", "catch", "throw",
		"loop", "eval", "exec", "system", "spawn", "sleep", "exit", "abort",
		"at_exit", "caller", "caller_locations", "global_variables",
		"local_variables", "rand", "srand", "Array", "Hash", "String",
		"Integer", "Float", "Complex", "Rational", "format", "sprintf",
		"lambda", "proc", "block_given?", "iterator?", "method_missing",
		"class", "clone", "dup", "extend", "freeze", "frozen?", "hash",
		"inspect", "instance_of?", "is_a?", "kind_of?", "method", "methods",
		"nil?", "object_id", "respond_to?", "send", "singleton_class",
		"taint", "tainted?", "to_s", "untaint",
		"each", "map", "collect", "select", "filter", "reject", "find",
		"detect", "find_all", "reduce", "inject", "sort", "sort_by",
		"group_by", "partition", "all?", "any?", "none?", "one?", "count",
		"min", "max", "minmax", "first", "take", "drop", "zip",
		"push", "pop", "shift", "unshift", "insert", "delete", "delete_at",
		"clear", "length", "size", "empty?", "include?", "index", "reverse",
		"join", "slice", "flatten", "compact", "uniq", "concat",
		"keys", "values", "each_key", "each_value", "has_key?", "key?",
		"has_value?", "value?", "fetch", "store", "delete", "merge",
		"upcase", "downcase", "capitalize", "swapcase", "reverse", "length",
		"size", "empty?", "split", "chars", "bytes", "strip", "chomp", "chop",
		"gsub", "sub", "match", "scan", "start_with?", "end_with?", "include?",
	}
	for _, f := range rubyBuiltins {
		bd.rubyBuiltins[f] = true
	}
	log.Printf("Loaded %d Ruby built-in methods from fallback list", len(rubyBuiltins))
}

func (bd *BuiltinDetector) loadRustBuiltins() {
	rustBuiltins := []string{
		"println!", "print!", "format!", "vec!", "panic!", "assert!", "assert_eq!",
		"assert_ne!", "debug_assert!", "debug_assert_eq!", "debug_assert_ne!",
		"write!", "writeln!", "todo!", "unimplemented!", "unreachable!",
		"matches!", "include!", "include_str!", "include_bytes!", "concat!",
		"stringify!", "file!", "line!", "column!", "module_path!", "cfg!",
		"env!", "option_env!", "compile_error!",
		"println", "print", "format", "vec", "panic", "assert", "assert_eq",
		"assert_ne", "debug_assert", "debug_assert_eq", "debug_assert_ne",
		"write", "writeln", "todo", "unimplemented", "unreachable",
		"matches", "include", "include_str", "include_bytes", "concat",
		"stringify", "file", "line", "column", "module_path", "cfg",
		"env", "option_env", "compile_error",
		"Option", "Some", "None", "Result", "Ok", "Err", "String", "Vec",
		"Box", "Rc", "Arc", "Cell", "RefCell", "Cow",
		"Clone", "clone", "Copy", "Send", "Sync", "Drop", "drop",
		"Iterator", "next", "collect", "map", "filter", "fold", "for_each",
		"find", "any", "all", "count", "sum", "product",
		"From", "from", "Into", "into", "TryFrom", "try_from", "TryInto", "try_into",
		"ToString", "to_string", "Default", "default",
		"len", "is_empty", "push", "pop", "insert", "remove", "clear",
		"get", "get_mut", "iter", "iter_mut", "split", "join", "contains",
		"starts_with", "ends_with", "trim", "parse", "unwrap", "expect",
		"unwrap_or", "unwrap_or_else", "map_or", "map_or_else", "and_then",
		"or_else", "ok_or", "ok_or_else",
	}
	for _, f := range rustBuiltins {
		bd.rustBuiltins[f] = true
	}
	log.Printf("Loaded %d Rust standard library items and macros", len(rustBuiltins))
}
