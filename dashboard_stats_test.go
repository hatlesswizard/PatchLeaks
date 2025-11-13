package main

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func expectedCWE(id string) string {
	name, ok := GetCWEName(id)
	if !ok || name == "" {
		return fmt.Sprintf("CWE-%s", id)
	}
	return fmt.Sprintf("CWE-%s: %s", id, name)
}

func TestExtractCWEsFromAIResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Single CWE with colon separator",
			input:    "CWE-117: Improper Output Neutralization for Logs",
			expected: []string{expectedCWE("117")},
		},
		{
			name:     "Single CWE with dash separator",
			input:    "CWE-532 - Insertion of Sensitive Information into Log File",
			expected: []string{expectedCWE("532")},
		},
		{
			name:     "Multiple CWEs in text",
			input:    "Vulnerability Existed: yes\nCWE-117: Improper Output Neutralization for Logs - file.ts [49]\nOld Code: debug log\nCWE-532: Insertion of Sensitive Information into Log File",
			expected: []string{expectedCWE("117"), expectedCWE("532")},
		},
		{
			name:     "CWE without description",
			input:    "Found CWE-200 in the code",
			expected: []string{expectedCWE("200")},
		},
		{
			name:     "Real AI response example",
			input:    "Vulnerability Existed: yes  \nCWE-117 - Improper Output Neutralization for Logs - packages/apps-engine/src/server/runtime/deno/ProcessMessenger.ts [49]  \n[Old Code]  \n```typescript\nprivate strategySend(message: JsonRpc) {\n\tthis.debug('Sending message to subprocess %o', message);\n\tthis.deno.stdin.write(this.encoder.encode(message));\n}\n```",
			expected: []string{expectedCWE("117")},
		},
		{
			name:     "Multiple vulnerabilities with different CWEs",
			input:    "Vulnerability Existed: yes\nCWE-1333 - Inefficient Regular Expression Complexity - apps/meteor/app/livechat/server/hooks/leadCapture.ts [37-41]\nOld Code: phoneRegexp pattern\nCWE-200: Information Exposure - path/to/file.php",
			expected: []string{expectedCWE("1333"), expectedCWE("200")},
		},
		{
			name:     "No CWE in response",
			input:    "No vulnerabilities found in this file",
			expected: []string{},
		},
		{
			name:     "CWE with parenthetical description",
			input:    "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
			expected: []string{expectedCWE("79")},
		},
		{
			name:     "CWE at line start with dash",
			input:    "CWE-89 - SQL Injection\nThis is a serious vulnerability",
			expected: []string{expectedCWE("89")},
		},
		{
			name:     "Mixed separators",
			input:    "CWE-22: Path Traversal found\nAlso CWE-78 - OS Command Injection detected",
			expected: []string{expectedCWE("22"), expectedCWE("78")},
		},
		{
			name:     "CWE with file path in description",
			input:    "CWE-601: URL Redirection to Untrusted Site ('Open Redirect') - src/auth/login.php Lines 42-45",
			expected: []string{expectedCWE("601")},
		},
		{
			name:     "Empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "CWE with newline in description should stop at newline",
			input:    "CWE-94: Improper Control of Generation of Code\nThis affects multiple files",
			expected: []string{expectedCWE("94")},
		},
		{
			name:     "Duplicate CWEs should be deduplicated",
			input:    "CWE-117: Improper Output Neutralization for Logs\nCWE-117: Improper Output Neutralization for Logs",
			expected: []string{expectedCWE("117")},
		},
		{
			name:     "CWE with numbers in description",
			input:    "CWE-327: Use of a Broken or Risky Cryptographic Algorithm (MD5/SHA1)",
			expected: []string{expectedCWE("327")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCWEsFromAIResponse(tt.input)
			sort.Strings(result)
			sort.Strings(tt.expected)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("extractCWEsFromAIResponse() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractCWEsFromAIResponseRealWorld(t *testing.T) {
	realAIResponse := `Vulnerability Existed: yes
CWE-117: Improper Output Neutralization for Logs - CWE-117 - packages/apps-engine/src/server/runtime/deno/AppsEngineDenoRuntime.ts [181, 324, 428, 526, 551, 646, 695]
Old Code: Various debug statements using %O and %o format specifiers
Fixed Code: Various debug statements using %s format specifier with util.inspect()
Vulnerability Existed: yes
CWE-532: Insertion of Sensitive Information into Log File - CWE-532 - packages/apps-engine/src/server/runtime/deno/AppsEngineDenoRuntime.ts [181, 324, 428, 526, 551, 646, 695]
Old Code: Various debug statements logging potentially sensitive data like options, environment, message content, parameters, and error messages
Fixed Code: Same debug statements but using util.inspect() with depth limitation for safer logging`
	expected := []string{expectedCWE("117"), expectedCWE("532")}
	result := extractCWEsFromAIResponse(realAIResponse)
	sort.Strings(result)
	sort.Strings(expected)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Real world example failed:\nGot:  %v\nWant: %v", result, expected)
	}
}
