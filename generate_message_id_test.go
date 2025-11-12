package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
)


func TestGenerateMessageIdDirectLookup(t *testing.T) {
	filePath := "cache/phpbb_release-3.3.14/phpBB/includes/functions_messenger.php"
	
	
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatalf("Test file does not exist: %s", filePath)
	}
	
	fmt.Printf("✓ File exists: %s\n", filePath)
	
	
	sig, body, err := TSFindPHPMethod(filePath, "generate_message_id")
	if err != nil {
		t.Errorf("❌ TSFindPHPMethod failed: %v", err)
	} else {
		fmt.Printf("✓ Found via TSFindPHPMethod\n")
		fmt.Printf("  Signature: %s\n", sig)
		fmt.Printf("  Body preview: %s...\n", truncate(body, 100))
	}
	
	
	if !strings.Contains(sig, "generate_message_id") {
		t.Errorf("❌ Signature doesn't contain method name: %s", sig)
	} else {
		fmt.Printf("✓ Signature contains method name\n")
	}
	
	
	if !strings.Contains(body, "md5(unique_id(time()))") {
		t.Errorf("❌ Body doesn't contain expected code: %s", truncate(body, 200))
	} else {
		fmt.Printf("✓ Body contains expected code\n")
	}
}


func TestGenerateMessageIdInMethodIndex(t *testing.T) {
	filePath := "cache/phpbb_release-3.3.14/phpBB/includes/functions_messenger.php"
	
	
	methods, err := TSListPHPMethodsInFile(filePath)
	if err != nil {
		t.Fatalf("❌ Failed to list PHP methods: %v", err)
	}
	
	fmt.Printf("✓ Found %d methods in file\n", len(methods))
	fmt.Printf("  Methods: %v\n", methods)
	
	
	found := false
	for _, method := range methods {
		if method == "generate_message_id" {
			found = true
			break
		}
	}
	
	if !found {
		t.Errorf("❌ generate_message_id not found in method list")
	} else {
		fmt.Printf("✓ generate_message_id found in method list\n")
	}
}


func TestBuildHeaderCallsGenerateMessageId(t *testing.T) {
	filePath := "cache/phpbb_release-3.3.14/phpBB/includes/functions_messenger.php"
	
	
	
	calls, bodies, err := TSListCalledFunctionsPHPMethod(filePath, "build_header")
	if err != nil {
		t.Fatalf("❌ Failed to list called functions: %v", err)
	}
	
	fmt.Printf("✓ Found %d function calls in build_header\n", len(calls))
	fmt.Printf("  Called functions: %v\n", calls)
	
	
	found := false
	for _, call := range calls {
		if call == "generate_message_id" {
			found = true
			break
		}
	}
	
	if !found {
		t.Errorf("❌ generate_message_id not found in calls from build_header")
		fmt.Printf("  This suggests the method call extraction is not working properly\n")
	} else {
		fmt.Printf("✓ generate_message_id found in calls from build_header\n")
		
		
		if body, ok := bodies["generate_message_id"]; ok {
			fmt.Printf("✓ Body retrieved for generate_message_id\n")
			fmt.Printf("  Body preview: %s...\n", truncate(body, 100))
		} else {
			t.Errorf("❌ Body not retrieved for generate_message_id")
		}
	}
}


func TestLazyFunctionIndex(t *testing.T) {
	repoPath := "cache/phpbb_release-3.3.14"
	
	
	lazyIndex := NewLazyFunctionIndex(repoPath)
	
	fmt.Printf("✓ Created LazyFunctionIndex for: %s\n", repoPath)
	
	
	def, err := lazyIndex.FindFunction("php", "generate_message_id")
	if err != nil {
		t.Errorf("❌ LazyFunctionIndex.FindFunction failed: %v", err)
		fmt.Printf("  This means the function lookup in the index is failing\n")
	} else {
		fmt.Printf("✓ Found via LazyFunctionIndex\n")
		fmt.Printf("  Name: %s\n", def.Name)
		fmt.Printf("  Language: %s\n", def.Language)
		fmt.Printf("  File: %s\n", filepath.Base(def.File))
		fmt.Printf("  IsMethod: %v\n", def.IsMethod)
		fmt.Printf("  Signature: %s\n", def.Signature)
		fmt.Printf("  Body preview: %s...\n", truncate(def.Body, 100))
	}
}


func TestExtractFunctionContext(t *testing.T) {
	filePath := "cache/phpbb_release-3.3.14/phpBB/includes/functions_messenger.php"
	repoPath := "cache/phpbb_release-3.3.14"
	
	
	diffContent := `
-		return md5(unique_id(time())) . '@' . $domain;
+		return sha256(unique_id(time())) . '@' . $domain;
`
	
	fmt.Printf("Testing with diff:\n%s\n", diffContent)
	
	context, err := ExtractFunctionContext(filePath, diffContent, true, repoPath)
	if err != nil {
		t.Errorf("❌ ExtractFunctionContext failed: %v", err)
	} else {
		if context == "" {
			t.Errorf("❌ Context is empty")
			fmt.Printf("  This means no functions were extracted from the diff\n")
		} else {
			fmt.Printf("✓ Context extracted (length: %d)\n", len(context))
			fmt.Printf("Context:\n%s\n", context)
			
			
			if strings.Contains(context, "generate_message_id") {
				fmt.Printf("✓ generate_message_id appears in context\n")
			} else {
				t.Errorf("❌ generate_message_id does not appear in context")
			}
		}
	}
}


func TestPHPFileCache(t *testing.T) {
	filePath := "cache/phpbb_release-3.3.14/phpBB/includes/functions_messenger.php"
	
	
	cache, err := getOrParsePHPFile(filePath)
	if err != nil {
		t.Fatalf("❌ Failed to parse PHP file: %v", err)
	}
	
	fmt.Printf("✓ PHP file parsed and cached\n")
	fmt.Printf("  Function index size: %d\n", len(cache.funcIndex))
	fmt.Printf("  Method index size: %d\n", len(cache.methodIndex))
	
	
	if len(cache.funcIndex) > 0 {
		fmt.Printf("  Functions: ")
		for name := range cache.funcIndex {
			fmt.Printf("%s ", name)
		}
		fmt.Printf("\n")
	}
	
	
	if len(cache.methodIndex) > 0 {
		fmt.Printf("  Methods: ")
		for name := range cache.methodIndex {
			fmt.Printf("%s ", name)
		}
		fmt.Printf("\n")
	}
	
	
	if _, exists := cache.methodIndex["generate_message_id"]; exists {
		fmt.Printf("✓ generate_message_id found in methodIndex\n")
	} else {
		t.Errorf("❌ generate_message_id NOT found in methodIndex")
		fmt.Printf("  Available methods: %v\n", getMapKeysFromNodeMap(cache.methodIndex))
	}
}


func TestIdentifyChangedFunctions(t *testing.T) {
	filePath := "cache/phpbb_release-3.3.14/phpBB/includes/functions_messenger.php"
	
	
	diffContent := `
@@ -466,7 +466,7 @@ class messenger
 	function generate_message_id()
 	{
 		global $config, $request;
-		$domain = ($config['server_name']) ?: $request->server('SERVER_NAME', 'phpbb.generated');
+		$domain = ($config['server_name']) ? $config['server_name'] : $request->server('SERVER_NAME', 'phpbb.generated');
 		return md5(unique_id(time())) . '@' . $domain;
 	}
`
	
	changedFuncs := identifyChangedFunctionsFromDiff(filePath, diffContent, "php")
	
	fmt.Printf("Changed functions identified: %v\n", changedFuncs)
	
	if len(changedFuncs) == 0 {
		t.Errorf("❌ No changed functions identified")
		fmt.Printf("  This means the diff parsing is not identifying changed functions\n")
	} else {
		fmt.Printf("✓ Found %d changed function(s)\n", len(changedFuncs))
		
		
		found := false
		for _, name := range changedFuncs {
			if name == "generate_message_id" {
				found = true
				break
			}
		}
		
		if !found {
			t.Errorf("❌ generate_message_id not in changed functions list")
		} else {
			fmt.Printf("✓ generate_message_id identified as changed\n")
		}
	}
}


func TestFullFileAddedScenario(t *testing.T) {
	filePath := "cache/phpbb_release-3.3.14/phpBB/includes/functions_messenger.php"
	repoPath := "cache/phpbb_release-3.3.14"
	
	
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("❌ Failed to read file: %v", err)
	}
	
	
	lines := strings.Split(string(content), "\n")
	var diffLines []string
	diffLines = append(diffLines, "--- /dev/null")
	diffLines = append(diffLines, fmt.Sprintf("+++ %s", filePath))
	diffLines = append(diffLines, fmt.Sprintf("@@ -0,0 +1,%d @@", len(lines)))
	for _, line := range lines {
		diffLines = append(diffLines, "+"+line)
	}
	diffContent := strings.Join(diffLines, "\n")
	
	fmt.Printf("Testing with full file diff (%d lines, %d bytes)\n", len(lines), len(diffContent))
	
	context, err := ExtractFunctionContext(filePath, diffContent, true, repoPath)
	if err != nil {
		t.Errorf("❌ ExtractFunctionContext failed: %v", err)
	} else {
		fmt.Printf("✓ Context extracted (length: %d bytes)\n", len(context))
		
		if context == "" {
			fmt.Printf("⚠️  Context is empty - this might be expected for full file diffs\n")
		} else {
			
			functionCount := strings.Count(context, "[Function:")
			fmt.Printf("  Function definitions in context: %d\n", functionCount)
			
			
			if strings.Contains(context, "generate_message_id") {
				fmt.Printf("✓ generate_message_id appears in context\n")
			} else {
				fmt.Printf("⚠️  generate_message_id does NOT appear in context\n")
			}
			
			
			fmt.Printf("\nContext preview (first 500 chars):\n%s\n", context)
		}
	}
}


func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}


func getMapKeysFromNodeMap(m map[string]*sitter.Node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
