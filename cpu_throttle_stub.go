package main
import (
	"math"
	"runtime/metrics"
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
	lastCPUSeconds float64
	mutex         sync.RWMutex
	enabled       bool
}
func InitCPUThrottler(limit float64) {
	throttlerInitMux.Do(func() {
		var samples = make([]metrics.Sample, 1)
		samples[0].Name = "/process/cpu:cpu-seconds"
		metrics.Read(samples)
		var startCPUSeconds float64
		if samples[0].Value.Kind() == metrics.KindFloat64 {
			startCPUSeconds = samples[0].Value.Float64()
		}
		cpuThrottler = &CPUThrottler{
			maxCPUPercent: limit,
			checkInterval: 100 * time.Millisecond,
			lastCheck:     time.Now(),
			lastCPUSeconds: startCPUSeconds,
			enabled:       true,
		}
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
	
	if elapsed < cpuThrottler.checkInterval {
		return
	}
	
	var samples = make([]metrics.Sample, 1)
	samples[0].Name = "/process/cpu:cpu-seconds"
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindFloat64 {
		cpuThrottler.lastCheck = now
		return
	}
	currentCPUSeconds := samples[0].Value.Float64()
	
	elapsedSeconds := elapsed.Seconds()
	if elapsedSeconds <= 0 {
		cpuThrottler.lastCheck = now
		return
	}
	deltaCPUSeconds := currentCPUSeconds - cpuThrottler.lastCPUSeconds
	if deltaCPUSeconds < 0 {
		
		deltaCPUSeconds = 0
	}
	totalCoreSeconds := elapsedSeconds * float64(runtime.NumCPU())
	var utilizationPercent float64
	if totalCoreSeconds > 0 {
		utilizationPercent = (deltaCPUSeconds / totalCoreSeconds) * 100.0
	} else {
		utilizationPercent = 0
	}
	cpuThrottler.lastCheck = now
	cpuThrottler.lastCPUSeconds = currentCPUSeconds
	
	if utilizationPercent > cpuThrottler.maxCPUPercent {
		overage := utilizationPercent - cpuThrottler.maxCPUPercent
		
		sleepFrac := math.Min(overage/100.0, 0.5)
		sleepDur := time.Duration(float64(cpuThrottler.checkInterval) * sleepFrac)
		if sleepDur > 0 {
			cpuThrottler.mutex.Unlock()
			time.Sleep(sleepDur)
			cpuThrottler.mutex.Lock()
		}
	}
}
