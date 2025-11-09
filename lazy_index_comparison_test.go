package main

import (
	"log"
	"os"
	"runtime"
	"testing"
	"time"
)


func TestLazyVsEagerSmallRepo(t *testing.T) {
	repoPath := "cache/cobra_go_1_7_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found", repoPath)
	}

	
	testFunctions := []string{"Execute", "AddCommand", "SetArgs", "Run", "PersistentFlags"}

	t.Logf("=== EAGER INDEXING (Original) ===")
	
	
	indexCacheMu.Lock()
	delete(functionIndexCache, repoPath)
	delete(indexBuildOnce, repoPath)
	indexCacheMu.Unlock()

	eagerStart := time.Now()
	eagerIndex, err := GetOrBuildFunctionIndex(repoPath)
	if err != nil {
		t.Fatalf("Eager index failed: %v", err)
	}
	eagerBuildTime := time.Since(eagerStart)
	
	eagerLookupStart := time.Now()
	eagerFound := 0
	for _, funcName := range testFunctions {
		paths := eagerIndex.FindFunction("go", funcName)
		if len(paths) > 0 {
			eagerFound++
		}
	}
	eagerLookupTime := time.Since(eagerLookupStart)
	eagerTotal := eagerBuildTime + eagerLookupTime

	t.Logf("Build time: %v", eagerBuildTime)
	t.Logf("Lookup time: %v", eagerLookupTime)
	t.Logf("Total time: %v", eagerTotal)
	t.Logf("Functions found: %d/%d", eagerFound, len(testFunctions))

	t.Logf("\n=== LAZY INDEXING (New) ===")
	
	lazyStart := time.Now()
	lazyIndex := NewLazyFunctionIndex(repoPath)
	lazyInitTime := time.Since(lazyStart)

	lazyLookupStart := time.Now()
	lazyFound := 0
	for _, funcName := range testFunctions {
		def, err := lazyIndex.FindFunction("go", funcName)
		if err == nil && def != nil {
			lazyFound++
		}
	}
	lazyLookupTime := time.Since(lazyLookupStart)
	lazyTotal := lazyInitTime + lazyLookupTime

	t.Logf("Init time: %v", lazyInitTime)
	t.Logf("Lookup time: %v", lazyLookupTime)
	t.Logf("Total time: %v", lazyTotal)
	t.Logf("Functions found: %d/%d", lazyFound, len(testFunctions))
	
	cacheHits, cacheMisses := lazyIndex.GetCacheStats()
	t.Logf("Cache hits: %d, misses: %d", cacheHits, cacheMisses)

	t.Logf("\n=== COMPARISON ===")
	speedup := float64(eagerTotal) / float64(lazyTotal)
	t.Logf("Speedup: %.2fx", speedup)
	t.Logf("Time saved: %v (%.1f%%)", eagerTotal-lazyTotal, (1.0-1.0/speedup)*100)

	if speedup < 1.5 {
		t.Logf("WARNING: Lazy indexing not significantly faster (%.2fx)", speedup)
	} else {
		t.Logf("SUCCESS: Lazy indexing is %.2fx faster!", speedup)
	}
}


func TestLazyVsEagerLargeRepo(t *testing.T) {
	repoPath := "cache/guava_java_32_1_1"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found", repoPath)
	}

	
	testFunctions := []string{"size", "isEmpty", "contains", "add", "remove", "clear", "toString"}

	t.Logf("=== EAGER INDEXING (Original) - Large Repo ===")
	
	
	indexCacheMu.Lock()
	delete(functionIndexCache, repoPath)
	delete(indexBuildOnce, repoPath)
	indexCacheMu.Unlock()

	eagerStart := time.Now()
	eagerIndex, err := GetOrBuildFunctionIndex(repoPath)
	if err != nil {
		t.Fatalf("Eager index failed: %v", err)
	}
	eagerBuildTime := time.Since(eagerStart)
	
	eagerLookupStart := time.Now()
	eagerFound := 0
	for _, funcName := range testFunctions {
		paths := eagerIndex.FindFunction("java", funcName)
		if len(paths) > 0 {
			eagerFound++
		}
	}
	eagerLookupTime := time.Since(eagerLookupStart)
	eagerTotal := eagerBuildTime + eagerLookupTime

	t.Logf("Build time: %v", eagerBuildTime)
	t.Logf("Lookup time: %v", eagerLookupTime)
	t.Logf("Total time: %v", eagerTotal)
	t.Logf("Functions found: %d/%d", eagerFound, len(testFunctions))

	t.Logf("\n=== LAZY INDEXING (New) - Large Repo ===")
	
	lazyStart := time.Now()
	lazyIndex := NewLazyFunctionIndex(repoPath)
	lazyInitTime := time.Since(lazyStart)

	lazyLookupStart := time.Now()
	lazyFound := 0
	for _, funcName := range testFunctions {
		def, err := lazyIndex.FindFunction("java", funcName)
		if err == nil && def != nil {
			lazyFound++
		}
	}
	lazyLookupTime := time.Since(lazyLookupStart)
	lazyTotal := lazyInitTime + lazyLookupTime

	t.Logf("Init time: %v", lazyInitTime)
	t.Logf("Lookup time: %v", lazyLookupTime)
	t.Logf("Total time: %v", lazyTotal)
	t.Logf("Functions found: %d/%d", lazyFound, len(testFunctions))
	
	cacheHits, cacheMisses := lazyIndex.GetCacheStats()
	t.Logf("Cache hits: %d, misses: %d", cacheHits, cacheMisses)

	t.Logf("\n=== COMPARISON (Large Repo) ===")
	speedup := float64(eagerTotal) / float64(lazyTotal)
	t.Logf("Speedup: %.2fx", speedup)
	t.Logf("Time saved: %v (%.1f%%)", eagerTotal-lazyTotal, (1.0-1.0/speedup)*100)

	if speedup < 2.0 {
		t.Logf("WARNING: Expected >2x speedup on large repo, got %.2fx", speedup)
	} else {
		t.Logf("SUCCESS: Lazy indexing is %.2fx faster on large repo!", speedup)
	}

	
	t.Logf("\nCache efficiency: %d hits, %d misses (%.1f%% hit rate)",
		cacheHits, cacheMisses, float64(cacheHits)/float64(cacheHits+cacheMisses)*100)
}


func TestRealWorldScenarioWithLazy(t *testing.T) {
	repoPath := "cache/gin_go_1_9_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found", repoPath)
	}

	
	functionLookups := []string{
		"ServeHTTP", "Handle", "GET", "POST", "PUT", "DELETE",
		"Bind", "BindJSON", "JSON", "String", "HTML",
		"Use", "Group", "Run", "RunTLS", "Abort",
		"Set", "Get", "Next", "Status", "Redirect",
	}

	t.Logf("=== REAL WORLD SCENARIO ===")
	t.Logf("Simulating analysis with %d function lookups", len(functionLookups))

	startTime := time.Now()
	lazyIndex := NewLazyFunctionIndex(repoPath)
	
	found := 0
	for _, funcName := range functionLookups {
		def, err := lazyIndex.FindFunction("go", funcName)
		if err == nil && def != nil {
			found++
		}
	}
	
	totalTime := time.Since(startTime)
	cacheHits, cacheMisses := lazyIndex.GetCacheStats()

	t.Logf("Total time: %v", totalTime)
	t.Logf("Functions found: %d/%d", found, len(functionLookups))
	t.Logf("Avg time per lookup: %v", totalTime/time.Duration(len(functionLookups)))
	t.Logf("Cache hits: %d, misses: %d", cacheHits, cacheMisses)
	t.Logf("Hit rate: %.1f%%", float64(cacheHits)/float64(cacheHits+cacheMisses)*100)

	if totalTime.Milliseconds() > 500 {
		t.Logf("WARNING: Took over 500ms for %d lookups", len(functionLookups))
	} else {
		t.Logf("SUCCESS: Completed %d lookups in %v", len(functionLookups), totalTime)
	}
}


func TestConcurrentLazyLookups(t *testing.T) {
	repoPath := "cache/cobra_go_1_7_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found", repoPath)
	}

	lazyIndex := NewLazyFunctionIndex(repoPath)
	
	
	testFunctions := []string{"Execute", "AddCommand", "SetArgs", "Run", "PersistentFlags"}
	
	t.Logf("Testing concurrent lookups with %d goroutines", 10)
	startTime := time.Now()
	
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for _, funcName := range testFunctions {
				lazyIndex.FindFunction("go", funcName)
			}
			done <- true
		}(i)
	}
	
	
	for i := 0; i < 10; i++ {
		<-done
	}
	
	totalTime := time.Since(startTime)
	cacheHits, cacheMisses := lazyIndex.GetCacheStats()
	
	t.Logf("Total time: %v", totalTime)
	t.Logf("Cache hits: %d, misses: %d", cacheHits, cacheMisses)
	t.Logf("Lookups per second: %.0f", float64(10*len(testFunctions))/totalTime.Seconds())
	
	if totalTime.Milliseconds() > 1000 {
		t.Logf("WARNING: Concurrent lookups took over 1 second")
	} else {
		t.Logf("SUCCESS: Concurrent lookups completed in %v", totalTime)
	}
}


func TestMemoryUsageComparison(t *testing.T) {
	repoPath := "cache/guava_java_32_1_1"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		t.Skipf("Test repo %s not found", repoPath)
	}

	
	log.SetOutput(os.Stderr)
	defer log.SetOutput(os.Stdout)

	t.Logf("=== MEMORY USAGE COMPARISON ===")
	
	
	indexCacheMu.Lock()
	delete(functionIndexCache, repoPath)
	delete(indexBuildOnce, repoPath)
	indexCacheMu.Unlock()

	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	
	eagerIndex, _ := GetOrBuildFunctionIndex(repoPath)
	_ = eagerIndex
	
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	eagerMem := m2.Alloc - m1.Alloc
	
	t.Logf("Eager index memory: %.2f MB", float64(eagerMem)/(1024*1024))

	
	var m3 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m3)
	
	lazyIndex := NewLazyFunctionIndex(repoPath)
	
	testFuncs := []string{"size", "isEmpty", "contains", "add", "remove"}
	for _, fn := range testFuncs {
		lazyIndex.FindFunction("java", fn)
	}
	
	var m4 runtime.MemStats
	runtime.ReadMemStats(&m4)
	lazyMem := m4.Alloc - m3.Alloc
	
	t.Logf("Lazy index memory: %.2f MB", float64(lazyMem)/(1024*1024))
	
	memSaved := float64(eagerMem-lazyMem) / float64(eagerMem) * 100
	t.Logf("Memory saved: %.1f%%", memSaved)
	
	if memSaved > 0 {
		t.Logf("SUCCESS: Lazy index uses %.1f%% less memory", memSaved)
	}
}


func BenchmarkLazyVsEager(b *testing.B) {
	repoPath := "cache/cobra_go_1_7_0"
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		b.Skip("Test repo not found")
	}

	testFunctions := []string{"Execute", "AddCommand", "SetArgs"}

	b.Run("Eager", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			indexCacheMu.Lock()
			delete(functionIndexCache, repoPath)
			delete(indexBuildOnce, repoPath)
			indexCacheMu.Unlock()

			idx, _ := GetOrBuildFunctionIndex(repoPath)
			for _, fn := range testFunctions {
				idx.FindFunction("go", fn)
			}
		}
	})

	b.Run("Lazy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			idx := NewLazyFunctionIndex(repoPath)
			for _, fn := range testFunctions {
				idx.FindFunction("go", fn)
			}
		}
	})
}

