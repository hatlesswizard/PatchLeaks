package main

import (
	"fmt"
	sitter "github.com/smacker/go-tree-sitter"
	tsc "github.com/smacker/go-tree-sitter/c"
	tscpp "github.com/smacker/go-tree-sitter/cpp"
	tscsharp "github.com/smacker/go-tree-sitter/csharp"
	tsgolang "github.com/smacker/go-tree-sitter/golang"
	tsjava "github.com/smacker/go-tree-sitter/java"
	tsjs "github.com/smacker/go-tree-sitter/javascript"
	tsphp "github.com/smacker/go-tree-sitter/php"
	tspy "github.com/smacker/go-tree-sitter/python"
	tsruby "github.com/smacker/go-tree-sitter/ruby"
	tsrust "github.com/smacker/go-tree-sitter/rust"
	tsts "github.com/smacker/go-tree-sitter/typescript/typescript"
	"os"
	"path/filepath"
	"strings"
)

func TSFindPHPFunction(filePath string, name string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	lang := tsphp.GetLanguage()
	p := sitter.NewParser()
	p.SetLanguage(lang)
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findPHPFunctionByNameNode(root, src, name)
	if fn == nil {
		return "", "", fmt.Errorf("function %s not found", name)
	}
	text := string(src[fn.StartByte():fn.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSFindPHPMethod(filePath string, methodName string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsphp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	md := findPHPMethodByNameNode(root, src, methodName)
	if md == nil {
		return "", "", fmt.Errorf("method %s not found", methodName)
	}
	text := string(src[md.StartByte():md.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListPHPFunctions(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	lang := tsphp.GetLanguage()
	p := sitter.NewParser()
	p.SetLanguage(lang)
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectPHPFunctions(root, src, &out)
	return out, nil
}

func collectPHPFunctions(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "name" && ch.ChildCount() == 0 {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectPHPFunctions(node.Child(i), src, out)
	}
}

func findPHPFunctionByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "name" && ch.ChildCount() == 0 {
				ident := string(src[ch.StartByte():ch.EndByte()])
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findPHPFunctionByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func findPHPMethodByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "method_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "name" && ch.ChildCount() == 0 {
				ident := string(src[ch.StartByte():ch.EndByte()])
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findPHPMethodByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func TSFindPythonFunction(filePath string, name string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	lang := tspy.GetLanguage()
	p := sitter.NewParser()
	p.SetLanguage(lang)
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findPyFunctionByNameNode(root, src, name)
	if fn == nil {
		return "", "", fmt.Errorf("function %s not found", name)
	}
	text := string(src[fn.StartByte():fn.EndByte()])
	if nl := strings.IndexAny(text, "\n\r"); nl > 0 {
		signature = strings.TrimRight(text[:nl], "\r")
		body = strings.TrimLeft(text[nl+1:], "\n\r")
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListPythonFunctions(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	lang := tspy.GetLanguage()
	p := sitter.NewParser()
	p.SetLanguage(lang)
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectPyFunctions(root, src, &out)
	return out, nil
}

func collectPyFunctions(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectPyFunctions(node.Child(i), src, out)
	}
}

func TSListCalledFunctionsPHP(filePath string, funcName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsphp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findPHPFunctionByNameNode(root, src, funcName)
	if fn == nil {
		return nil, nil, fmt.Errorf("function %s not found", funcName)
	}
	var collected []string
	collectPHPCallNames(fn, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindPHPFunction(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
		}
	}
	return unique, resultBodies, nil
}

func collectPHPCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	t := node.Type()
	switch t {
	case "function_call_expression":
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "name" || ch.Type() == "name_or_reserved" || ch.Type() == "qualified_name" {
				if id := phpRightMostIdentifier(ch, src); id != "" {
					*out = append(*out, id)
				}
				break
			}
		}
	case "method_call_expression", "scoped_call_expression", "member_call_expression":
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "name" || ch.Type() == "qualified_name" || ch.Type() == "member_name" {
				if id := phpRightMostIdentifier(ch, src); id != "" {
					*out = append(*out, id)
				}
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectPHPCallNames(node.Child(i), src, out)
	}
}

func phpRightMostIdentifier(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	if node.Type() == "name" || node.Type() == "identifier" {
		return strings.TrimSpace(string(src[node.StartByte():node.EndByte()]))
	}
	if node.ChildCount() > 0 {
		return phpRightMostIdentifier(node.Child(int(node.ChildCount()-1)), src)
	}
	return ""
}

func detectRepoRootPHP(filePath string) string {
	dir := filepath.Dir(filePath)
	for i := 0; i < 8; i++ {
		base := filepath.Base(dir)
		if strings.HasPrefix(base, "phpbb_release-") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func scanPHPDefinitionInRepo(repoRoot string, name string) (signature string, body string, found bool) {
	var sig string
	var bd string
	found = false
	stopErr := fmt.Errorf("found")
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if low == ".git" || low == "node_modules" || low == "vendor" || low == "tests" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".php") {
			return nil
		}
		if s, b, e := TSFindPHPMethod(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		if s, b, e := TSFindPHPFunction(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		return nil
	})
	if found {
		return sig, bd, true
	}
	return "", "", false
}

func TSListCalledFunctionsPHPMethod(filePath string, methodName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsphp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	md := findPHPMethodByNameNode(root, src, methodName)
	if md == nil {
		return nil, nil, fmt.Errorf("method %s not found", methodName)
	}
	var collected []string
	collectPHPCallNames(md, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindPHPFunction(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if sig, body, e := TSFindPHPMethod(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if root := detectRepoRootPHP(filePath); root != "" {
			if s, b, ok := scanPHPDefinitionInRepo(root, n); ok {
				resultBodies[n] = s + "\n{\n" + b + "\n}"
			}
		}
	}
	return unique, resultBodies, nil
}

func TSListCalledFunctionsPython(filePath string, funcName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tspy.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findPyFunctionByNameNode(root, src, funcName)
	if fn == nil {
		return nil, nil, fmt.Errorf("function %s not found", funcName)
	}
	var collected []string
	collectPyCallNames(fn, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindPythonFunction(filePath, n); e == nil {
			resultBodies[n] = sig + "\n" + body
		}
	}
	return unique, resultBodies, nil
}

func collectPyCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "call" {
		if node.ChildCount() > 0 {
			f := node.Child(0)
			name := rightMostIdentifier(f, src)
			if name != "" {
				*out = append(*out, name)
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectPyCallNames(node.Child(i), src, out)
	}
}

func rightMostIdentifier(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	if node.Type() == "identifier" {
		return string(src[node.StartByte():node.EndByte()])
	}
	if node.ChildCount() > 0 {
		return rightMostIdentifier(node.Child(int(node.ChildCount()-1)), src)
	}
	return ""
}

func findPyFunctionByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				ident := string(src[ch.StartByte():ch.EndByte()])
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findPyFunctionByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func TSListPHPMethodsInFile(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	lang := tsphp.GetLanguage()
	p := sitter.NewParser()
	p.SetLanguage(lang)
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectPHPMethods(root, src, &out)
	return out, nil
}

func collectPHPMethods(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "method_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "name" && ch.ChildCount() == 0 {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectPHPMethods(node.Child(i), src, out)
	}
}

func TSFindCFunction(filePath string, name string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsc.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findCFunctionByNameNode(root, src, name)
	if fn == nil {
		return "", "", fmt.Errorf("function %s not found", name)
	}
	text := string(src[fn.StartByte():fn.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListCFunctions(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsc.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectCFunctions(root, src, &out)
	return out, nil
}

func TSListCalledFunctionsC(filePath string, funcName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsc.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findCFunctionByNameNode(root, src, funcName)
	if fn == nil {
		return nil, nil, fmt.Errorf("function %s not found", funcName)
	}
	var collected []string
	collectCCallNames(fn, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindCFunction(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if dir := filepath.Dir(filePath); dir != "" {
			if sig, body, ok := scanCDefinitionInRepo(dir, n); ok {
				resultBodies[n] = sig + "\n{\n" + body + "\n}"
			}
		}
	}
	return unique, resultBodies, nil
}

func scanCDefinitionInRepo(repoRoot string, name string) (signature string, body string, found bool) {
	var sig string
	var bd string
	found = false
	stopErr := fmt.Errorf("found")
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if low == ".git" || low == "node_modules" || low == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".c") && !strings.HasSuffix(strings.ToLower(path), ".h") {
			return nil
		}
		if s, b, e := TSFindCFunction(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		return nil
	})
	if found {
		return sig, bd, true
	}
	return "", "", false
}

func findCFunctionByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "function_declarator" {
				ident := extractCIdentifierFromDeclarator(ch, src)
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findCFunctionByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func extractCIdentifierFromDeclarator(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	if node.Type() == "identifier" {
		return string(src[node.StartByte():node.EndByte()])
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if id := extractCIdentifierFromDeclarator(node.Child(i), src); id != "" {
			return id
		}
	}
	return ""
}

func collectCFunctions(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "function_declarator" {
				ident := extractCIdentifierFromDeclarator(ch, src)
				if ident != "" {
					*out = append(*out, ident)
				}
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectCFunctions(node.Child(i), src, out)
	}
}

func collectCCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectCCallNames(node.Child(i), src, out)
	}
}

func TSFindCppFunction(filePath string, name string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tscpp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findCppFunctionByNameNode(root, src, name)
	if fn == nil {
		return "", "", fmt.Errorf("function %s not found", name)
	}
	text := string(src[fn.StartByte():fn.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSFindCppMethod(filePath string, methodName string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tscpp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	md := findCppMethodByNameNode(root, src, methodName)
	if md == nil {
		return "", "", fmt.Errorf("method %s not found", methodName)
	}
	text := string(src[md.StartByte():md.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListCppFunctions(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tscpp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectCppFunctions(root, src, &out)
	return out, nil
}

func TSListCppMethods(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tscpp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectCppMethods(root, src, &out)
	return out, nil
}

func TSListCalledFunctionsCpp(filePath string, methodName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tscpp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var targetNode *sitter.Node
	targetNode = findCppMethodByNameNode(root, src, methodName)
	if targetNode == nil {
		targetNode = findCppFunctionByNameNode(root, src, methodName)
	}
	if targetNode == nil {
		return nil, nil, fmt.Errorf("method/function %s not found", methodName)
	}
	var collected []string
	collectCppCallNames(targetNode, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindCppMethod(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if sig, body, e := TSFindCppFunction(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if dir := filepath.Dir(filePath); dir != "" {
			if sig, body, ok := scanCppDefinitionInRepo(dir, n); ok {
				resultBodies[n] = sig + "\n{\n" + body + "\n}"
			}
		}
	}
	return unique, resultBodies, nil
}

func scanCppDefinitionInRepo(repoRoot string, name string) (signature string, body string, found bool) {
	var sig string
	var bd string
	found = false
	stopErr := fmt.Errorf("found")
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if low == ".git" || low == "node_modules" || low == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".cpp" && ext != ".cc" && ext != ".cxx" && ext != ".hpp" && ext != ".h" {
			return nil
		}
		if s, b, e := TSFindCppMethod(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		if s, b, e := TSFindCppFunction(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		return nil
	})
	if found {
		return sig, bd, true
	}
	return "", "", false
}

func findCppFunctionByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "function_declarator" {
				ident := extractCppIdentifierFromDeclarator(ch, src)
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findCppFunctionByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func findCppMethodByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "function_declarator" {
				ident := extractCppIdentifierFromDeclarator(ch, src)
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findCppMethodByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func extractCppIdentifierFromDeclarator(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	if node.Type() == "identifier" {
		return string(src[node.StartByte():node.EndByte()])
	}
	if node.Type() == "field_identifier" {
		return string(src[node.StartByte():node.EndByte()])
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if id := extractCppIdentifierFromDeclarator(node.Child(i), src); id != "" {
			return id
		}
	}
	return ""
}

func collectCppFunctions(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "function_declarator" {
				ident := extractCppIdentifierFromDeclarator(ch, src)
				if ident != "" {
					*out = append(*out, ident)
				}
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectCppFunctions(node.Child(i), src, out)
	}
}

func collectCppMethods(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "function_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "function_declarator" {
				ident := extractCppIdentifierFromDeclarator(ch, src)
				if ident != "" {
					*out = append(*out, ident)
				}
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectCppMethods(node.Child(i), src, out)
	}
}

func collectCppCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" || ch.Type() == "field_identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
			if ch.Type() == "field_expression" {
				if fieldCh := ch.Child(int(ch.ChildCount() - 1)); fieldCh != nil && fieldCh.Type() == "field_identifier" {
					*out = append(*out, string(src[fieldCh.StartByte():fieldCh.EndByte()]))
					break
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectCppCallNames(node.Child(i), src, out)
	}
}

func TSFindCSharpMethod(filePath string, methodName string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tscsharp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	md := findCSharpMethodByNameNode(root, src, methodName)
	if md == nil {
		return "", "", fmt.Errorf("method %s not found", methodName)
	}
	text := string(src[md.StartByte():md.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListCSharpMethods(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tscsharp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectCSharpMethods(root, src, &out)
	return out, nil
}

func TSListCalledFunctionsCSharp(filePath string, methodName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tscsharp.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	md := findCSharpMethodByNameNode(root, src, methodName)
	if md == nil {
		return nil, nil, fmt.Errorf("method %s not found", methodName)
	}
	var collected []string
	collectCSharpCallNames(md, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindCSharpMethod(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if dir := filepath.Dir(filePath); dir != "" {
			if sig, body, ok := scanCSharpDefinitionInRepo(dir, n); ok {
				resultBodies[n] = sig + "\n{\n" + body + "\n}"
			}
		}
	}
	return unique, resultBodies, nil
}

func scanCSharpDefinitionInRepo(repoRoot string, name string) (signature string, body string, found bool) {
	var sig string
	var bd string
	found = false
	stopErr := fmt.Errorf("found")
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if low == ".git" || low == "node_modules" || low == "bin" || low == "obj" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".cs") {
			return nil
		}
		if s, b, e := TSFindCSharpMethod(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		return nil
	})
	if found {
		return sig, bd, true
	}
	return "", "", false
}

func findCSharpMethodByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "method_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				ident := string(src[ch.StartByte():ch.EndByte()])
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findCSharpMethodByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func collectCSharpMethods(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "method_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectCSharpMethods(node.Child(i), src, out)
	}
}

func collectCSharpCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "invocation_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
			if ch.Type() == "member_access_expression" {
				if rightmost := ch.Child(int(ch.ChildCount() - 1)); rightmost != nil && rightmost.Type() == "identifier" {
					*out = append(*out, string(src[rightmost.StartByte():rightmost.EndByte()]))
					break
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectCSharpCallNames(node.Child(i), src, out)
	}
}

func TSFindGoFunction(filePath string, name string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsgolang.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findGoFunctionByNameNode(root, src, name)
	if fn == nil {
		return "", "", fmt.Errorf("function %s not found", name)
	}
	text := string(src[fn.StartByte():fn.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListGoFunctions(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsgolang.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectGoFunctions(root, src, &out)
	return out, nil
}

func TSListCalledFunctionsGo(filePath string, funcName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsgolang.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findGoFunctionByNameNode(root, src, funcName)
	if fn == nil {
		return nil, nil, fmt.Errorf("function %s not found", funcName)
	}
	var collected []string
	collectGoCallNames(fn, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindGoFunction(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if dir := filepath.Dir(filePath); dir != "" {
			if sig, body, ok := scanGoDefinitionInRepo(dir, n); ok {
				resultBodies[n] = sig + "\n{\n" + body + "\n}"
			}
		}
	}
	return unique, resultBodies, nil
}

func scanGoDefinitionInRepo(repoRoot string, name string) (signature string, body string, found bool) {
	var sig string
	var bd string
	found = false
	stopErr := fmt.Errorf("found")
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if low == ".git" || low == "node_modules" || low == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".go") {
			return nil
		}
		if s, b, e := TSFindGoFunction(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		return nil
	})
	if found {
		return sig, bd, true
	}
	return "", "", false
}

func findGoFunctionByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "function_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				ident := string(src[ch.StartByte():ch.EndByte()])
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findGoFunctionByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func collectGoFunctions(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "function_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectGoFunctions(node.Child(i), src, out)
	}
}

func collectGoCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
			if ch.Type() == "selector_expression" {
				if rightmost := ch.Child(int(ch.ChildCount() - 1)); rightmost != nil && rightmost.Type() == "field_identifier" {
					*out = append(*out, string(src[rightmost.StartByte():rightmost.EndByte()]))
					break
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectGoCallNames(node.Child(i), src, out)
	}
}

func TSFindJavaMethod(filePath string, methodName string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsjava.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	md := findJavaMethodByNameNode(root, src, methodName)
	if md == nil {
		return "", "", fmt.Errorf("method %s not found", methodName)
	}
	text := string(src[md.StartByte():md.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListJavaMethods(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsjava.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectJavaMethods(root, src, &out)
	return out, nil
}

func TSListCalledFunctionsJava(filePath string, methodName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsjava.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	md := findJavaMethodByNameNode(root, src, methodName)
	if md == nil {
		return nil, nil, fmt.Errorf("method %s not found", methodName)
	}
	var collected []string
	collectJavaCallNames(md, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindJavaMethod(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if dir := filepath.Dir(filePath); dir != "" {
			if sig, body, ok := scanJavaDefinitionInRepo(dir, n); ok {
				resultBodies[n] = sig + "\n{\n" + body + "\n}"
			}
		}
	}
	return unique, resultBodies, nil
}

func scanJavaDefinitionInRepo(repoRoot string, name string) (signature string, body string, found bool) {
	var sig string
	var bd string
	found = false
	stopErr := fmt.Errorf("found")
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if low == ".git" || low == "node_modules" || low == "target" || low == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".java") {
			return nil
		}
		if s, b, e := TSFindJavaMethod(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		return nil
	})
	if found {
		return sig, bd, true
	}
	return "", "", false
}

func findJavaMethodByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "method_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				ident := string(src[ch.StartByte():ch.EndByte()])
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findJavaMethodByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func collectJavaMethods(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "method_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectJavaMethods(node.Child(i), src, out)
	}
}

func collectJavaCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "method_invocation" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
			if ch.Type() == "field_access" {
				if rightmost := ch.Child(int(ch.ChildCount() - 1)); rightmost != nil && rightmost.Type() == "identifier" {
					*out = append(*out, string(src[rightmost.StartByte():rightmost.EndByte()]))
					break
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectJavaCallNames(node.Child(i), src, out)
	}
}

func TSFindJSFunction(filePath string, name string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsjs.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findJSFunctionByNameNode(root, src, name)
	if fn == nil {
		return "", "", fmt.Errorf("function %s not found", name)
	}
	text := string(src[fn.StartByte():fn.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListJSFunctions(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsjs.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectJSFunctions(root, src, &out)
	return out, nil
}

func TSListCalledFunctionsJS(filePath string, funcName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsjs.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findJSFunctionByNameNode(root, src, funcName)
	if fn == nil {
		return nil, nil, fmt.Errorf("function %s not found", funcName)
	}
	var collected []string
	collectJSCallNames(fn, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindJSFunction(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if dir := filepath.Dir(filePath); dir != "" {
			if sig, body, ok := scanJSDefinitionInRepo(dir, n); ok {
				resultBodies[n] = sig + "\n{\n" + body + "\n}"
			}
		}
	}
	return unique, resultBodies, nil
}

func scanJSDefinitionInRepo(repoRoot string, name string) (signature string, body string, found bool) {
	var sig string
	var bd string
	found = false
	stopErr := fmt.Errorf("found")
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if low == ".git" || low == "node_modules" || low == "dist" || low == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".js" && ext != ".jsx" {
			return nil
		}
		if s, b, e := TSFindJSFunction(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		return nil
	})
	if found {
		return sig, bd, true
	}
	return "", "", false
}

func findJSFunctionByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "function_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				ident := string(src[ch.StartByte():ch.EndByte()])
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findJSFunctionByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func collectJSFunctions(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "function_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectJSFunctions(node.Child(i), src, out)
	}
}

func collectJSCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
			if ch.Type() == "member_expression" {
				if rightmost := ch.Child(int(ch.ChildCount() - 1)); rightmost != nil && rightmost.Type() == "property_identifier" {
					*out = append(*out, string(src[rightmost.StartByte():rightmost.EndByte()]))
					break
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectJSCallNames(node.Child(i), src, out)
	}
}

func TSFindRubyMethod(filePath string, methodName string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsruby.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	md := findRubyMethodByNameNode(root, src, methodName)
	if md == nil {
		return "", "", fmt.Errorf("method %s not found", methodName)
	}
	text := string(src[md.StartByte():md.EndByte()])
	if nl := strings.IndexAny(text, "\n\r"); nl > 0 {
		signature = strings.TrimRight(text[:nl], "\r")
		endStr := "end"
		endIdx := strings.LastIndex(text, endStr)
		if endIdx > nl {
			body = strings.TrimSpace(text[nl+1 : endIdx])
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListRubyMethods(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsruby.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectRubyMethods(root, src, &out)
	return out, nil
}

func TSListCalledFunctionsRuby(filePath string, methodName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsruby.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	md := findRubyMethodByNameNode(root, src, methodName)
	if md == nil {
		return nil, nil, fmt.Errorf("method %s not found", methodName)
	}
	var collected []string
	collectRubyCallNames(md, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindRubyMethod(filePath, n); e == nil {
			resultBodies[n] = sig + "\n" + body + "\nend"
			continue
		}
		if dir := filepath.Dir(filePath); dir != "" {
			if sig, body, ok := scanRubyDefinitionInRepo(dir, n); ok {
				resultBodies[n] = sig + "\n" + body + "\nend"
			}
		}
	}
	return unique, resultBodies, nil
}

func scanRubyDefinitionInRepo(repoRoot string, name string) (signature string, body string, found bool) {
	var sig string
	var bd string
	found = false
	stopErr := fmt.Errorf("found")
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if low == ".git" || low == "node_modules" || low == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".rb") {
			return nil
		}
		if s, b, e := TSFindRubyMethod(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		return nil
	})
	if found {
		return sig, bd, true
	}
	return "", "", false
}

func findRubyMethodByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "method" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				ident := string(src[ch.StartByte():ch.EndByte()])
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findRubyMethodByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func collectRubyMethods(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "method" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectRubyMethods(node.Child(i), src, out)
	}
}

func collectRubyCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "call" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectRubyCallNames(node.Child(i), src, out)
	}
}

func TSFindRustFunction(filePath string, name string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsrust.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findRustFunctionByNameNode(root, src, name)
	if fn == nil {
		return "", "", fmt.Errorf("function %s not found", name)
	}
	text := string(src[fn.StartByte():fn.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListRustFunctions(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsrust.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectRustFunctions(root, src, &out)
	return out, nil
}

func TSListCalledFunctionsRust(filePath string, funcName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsrust.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findRustFunctionByNameNode(root, src, funcName)
	if fn == nil {
		return nil, nil, fmt.Errorf("function %s not found", funcName)
	}
	var collected []string
	collectRustCallNames(fn, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindRustFunction(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if dir := filepath.Dir(filePath); dir != "" {
			if sig, body, ok := scanRustDefinitionInRepo(dir, n); ok {
				resultBodies[n] = sig + "\n{\n" + body + "\n}"
			}
		}
	}
	return unique, resultBodies, nil
}

func scanRustDefinitionInRepo(repoRoot string, name string) (signature string, body string, found bool) {
	var sig string
	var bd string
	found = false
	stopErr := fmt.Errorf("found")
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if low == ".git" || low == "node_modules" || low == "target" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".rs") {
			return nil
		}
		if s, b, e := TSFindRustFunction(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		return nil
	})
	if found {
		return sig, bd, true
	}
	return "", "", false
}

func findRustFunctionByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "function_item" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				ident := string(src[ch.StartByte():ch.EndByte()])
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findRustFunctionByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func collectRustFunctions(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "function_item" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectRustFunctions(node.Child(i), src, out)
	}
}

func collectRustCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
			if ch.Type() == "field_expression" {
				if rightmost := ch.Child(int(ch.ChildCount() - 1)); rightmost != nil && rightmost.Type() == "field_identifier" {
					*out = append(*out, string(src[rightmost.StartByte():rightmost.EndByte()]))
					break
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectRustCallNames(node.Child(i), src, out)
	}
}

func TSFindTSFunction(filePath string, name string) (signature string, body string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsts.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findTSFunctionByNameNode(root, src, name)
	if fn == nil {
		return "", "", fmt.Errorf("function %s not found", name)
	}
	text := string(src[fn.StartByte():fn.EndByte()])
	idx := strings.Index(text, "{")
	if idx > 0 {
		signature = strings.TrimSpace(text[:idx])
		endIdx := strings.LastIndex(text, "}")
		if endIdx > idx+1 {
			body = strings.TrimRight(text[idx+1:endIdx], "\n\r ")
		}
	} else {
		signature = strings.TrimSpace(text)
	}
	return signature, body, nil
}

func TSListTSFunctions(filePath string) ([]string, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsts.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	var out []string
	collectTSFunctions(root, src, &out)
	return out, nil
}

func TSListCalledFunctionsTS(filePath string, funcName string) (names []string, bodies map[string]string, err error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}
	p := sitter.NewParser()
	p.SetLanguage(tsts.GetLanguage())
	tree := p.Parse(nil, src)
	root := tree.RootNode()
	fn := findTSFunctionByNameNode(root, src, funcName)
	if fn == nil {
		return nil, nil, fmt.Errorf("function %s not found", funcName)
	}
	var collected []string
	collectTSCallNames(fn, src, &collected)
	seen := map[string]bool{}
	for _, n := range collected {
		seen[n] = true
	}
	var unique []string
	for n := range seen {
		unique = append(unique, n)
	}
	resultBodies := map[string]string{}
	for _, n := range unique {
		if sig, body, e := TSFindTSFunction(filePath, n); e == nil {
			resultBodies[n] = sig + "\n{\n" + body + "\n}"
			continue
		}
		if dir := filepath.Dir(filePath); dir != "" {
			if sig, body, ok := scanTSDefinitionInRepo(dir, n); ok {
				resultBodies[n] = sig + "\n{\n" + body + "\n}"
			}
		}
	}
	return unique, resultBodies, nil
}

func scanTSDefinitionInRepo(repoRoot string, name string) (signature string, body string, found bool) {
	var sig string
	var bd string
	found = false
	stopErr := fmt.Errorf("found")
	_ = filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			low := strings.ToLower(d.Name())
			if low == ".git" || low == "node_modules" || low == "dist" || low == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".ts" && ext != ".tsx" {
			return nil
		}
		if s, b, e := TSFindTSFunction(path, name); e == nil && s != "" {
			sig, bd, found = s, b, true
			return stopErr
		}
		return nil
	})
	if found {
		return sig, bd, true
	}
	return "", "", false
}

func findTSFunctionByNameNode(node *sitter.Node, src []byte, name string) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "function_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				ident := string(src[ch.StartByte():ch.EndByte()])
				if ident == name {
					return node
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if res := findTSFunctionByNameNode(node.Child(i), src, name); res != nil {
			return res
		}
	}
	return nil
}

func collectTSFunctions(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "function_declaration" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectTSFunctions(node.Child(i), src, out)
	}
}

func collectTSCallNames(node *sitter.Node, src []byte, out *[]string) {
	if node == nil {
		return
	}
	if node.Type() == "call_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			ch := node.Child(i)
			if ch.Type() == "identifier" {
				*out = append(*out, string(src[ch.StartByte():ch.EndByte()]))
				break
			}
			if ch.Type() == "member_expression" {
				if rightmost := ch.Child(int(ch.ChildCount() - 1)); rightmost != nil && rightmost.Type() == "property_identifier" {
					*out = append(*out, string(src[rightmost.StartByte():rightmost.EndByte()]))
					break
				}
			}
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		collectTSCallNames(node.Child(i), src, out)
	}
}
