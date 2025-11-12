package main
import (
	"testing"
)
func BenchmarkGetDashboardStats(b *testing.B) {
	InvalidateDashboardCache()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvalidateDashboardCache() 
		_, err := GetDashboardStats()
		if err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkExtractCWEsFromAIResponse(b *testing.B) {
	testResponse := `Vulnerability Existed: yes
CWE-117: Improper Output Neutralization for Logs - CWE-117 - packages/apps-engine/src/server/runtime/deno/AppsEngineDenoRuntime.ts [181, 324, 428]
Old Code: Various debug statements using %O and %o format specifiers
Fixed Code: Various debug statements using %s format specifier with util.inspect()
Vulnerability Existed: yes
CWE-532: Insertion of Sensitive Information into Log File - CWE-532 - packages/apps-engine/src/server/runtime/deno/AppsEngineDenoRuntime.ts [181]
Old Code: Various debug statements logging potentially sensitive data
CWE-79: Cross-Site Scripting found in file.php
CWE-89: SQL Injection in database.php`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractCWEsFromAIResponse(testResponse)
	}
}
func BenchmarkCalculateVulnerabilityMetrics(b *testing.B) {
	analyses := loadAllAnalyses()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateVulnerabilityMetrics(analyses)
	}
}
