package main

import (
	"log"
	"runtime"
	"sync"
	"time"
)

var (
	cpuThrottler     *CPUThrottler
	throttlerInitMux sync.Once
)

type CPUThrottler struct {
	maxCPUPercent float64
	checkInterval time.Duration
	lastCheck     time.Time
	lastCPUTime   time.Duration
	mutex         sync.RWMutex
	enabled       bool
}

func InitCPUThrottler(limit float64) {
	throttlerInitMux.Do(func() {
		cpuThrottler = &CPUThrottler{
			maxCPUPercent: limit,
			checkInterval: 100 * time.Millisecond,
			lastCheck:     time.Now(),
			enabled:       true,
		}
		log.Printf("CPU throttler initialized with %.0f%% limit", limit)
	})
}

func ThrottleYield() {
	if cpuThrottler == nil || !cpuThrottler.enabled {
		return
	}

	cpuThrottler.mutex.Lock()
	defer cpuThrottler.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(cpuThrottler.lastCheck)

	// Only check CPU every checkInterval to avoid overhead
	if elapsed < cpuThrottler.checkInterval {
		return
	}

	// Get current CPU stats
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	// Calculate CPU usage as percentage of cores
	numCPU := float64(runtime.NumCPU())
	numGoroutine := float64(runtime.NumGoroutine())

	// Estimate CPU usage based on goroutines and core count
	estimatedCPU := (numGoroutine / numCPU) * 100

	cpuThrottler.lastCheck = now

	// If estimated CPU is too high, add a small delay
	if estimatedCPU > cpuThrottler.maxCPUPercent {
		// Calculate sleep duration based on how much we're over the limit
		overagePercent := estimatedCPU - cpuThrottler.maxCPUPercent
		sleepMs := int(overagePercent * 2) // 2ms per 1% overage
		if sleepMs > 100 {
			sleepMs = 100 // Cap at 100ms
		}
		if sleepMs > 0 {
			cpuThrottler.mutex.Unlock()
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
			cpuThrottler.mutex.Lock()
		}
	}
}

func ThrottleYieldEvery(count int, interval int) {
	if cpuThrottler == nil || !cpuThrottler.enabled {
		return
	}

	// Only yield every N iterations
	if count%interval == 0 {
		ThrottleYield()
	}
}
