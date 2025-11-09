package main

import (
	"sync"
	"sync/atomic"
	"time"
)


type MetricsTracker struct {
	cacheHits        int64
	cacheMisses      int64
	downloadTimes    []float64
	downloadTimesMux sync.RWMutex
	newVersions      int64
	activeAIThreads  int32
}

var globalMetrics = &MetricsTracker{
	downloadTimes: make([]float64, 0, 100),
}


func TrackCacheHit() {
	atomic.AddInt64(&globalMetrics.cacheHits, 1)
}


func TrackCacheMiss() {
	atomic.AddInt64(&globalMetrics.cacheMisses, 1)
}


func TrackDownloadTime(duration time.Duration) {
	globalMetrics.downloadTimesMux.Lock()
	defer globalMetrics.downloadTimesMux.Unlock()

	seconds := duration.Seconds()
	globalMetrics.downloadTimes = append(globalMetrics.downloadTimes, seconds)

	
	if len(globalMetrics.downloadTimes) > 100 {
		globalMetrics.downloadTimes = globalMetrics.downloadTimes[1:]
	}
}


func TrackNewVersion() {
	atomic.AddInt64(&globalMetrics.newVersions, 1)
}


func IncrementActiveAIThreads() {
	atomic.AddInt32(&globalMetrics.activeAIThreads, 1)
}


func DecrementActiveAIThreads() {
	atomic.AddInt32(&globalMetrics.activeAIThreads, -1)
}


func getCacheHitStats() (int64, int64) {
	hits := atomic.LoadInt64(&globalMetrics.cacheHits)
	misses := atomic.LoadInt64(&globalMetrics.cacheMisses)
	return hits, misses
}


func getAvgDownloadTime() float64 {
	globalMetrics.downloadTimesMux.RLock()
	defer globalMetrics.downloadTimesMux.RUnlock()

	if len(globalMetrics.downloadTimes) == 0 {
		return 0
	}

	var sum float64
	for _, t := range globalMetrics.downloadTimes {
		sum += t
	}

	return sum / float64(len(globalMetrics.downloadTimes))
}


func getNewVersionsDetected() int {
	return int(atomic.LoadInt64(&globalMetrics.newVersions))
}


func getActiveAIThreads() int {
	return int(atomic.LoadInt32(&globalMetrics.activeAIThreads))
}
