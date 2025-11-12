package main
import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)
type DiskTracker struct {
	readBytes   int64
	writeBytes  int64
	readOps     int64
	writeOps    int64
	startTime   time.Time
	lastLogTime time.Time
	mu          sync.RWMutex
}
var globalDiskTracker = &DiskTracker{
	startTime:   time.Now(),
	lastLogTime: time.Now(),
}
var (
	logFile            *os.File
	logChannel         chan string
	logWriterStarted   bool
	logWriterMutex     sync.Mutex
	logWriterWaitGroup sync.WaitGroup
	droppedLogs        int64 // Counter for dropped log messages
)
func initLogFile() error {
	if logFile != nil {
		return nil
	}
	var err error
	logFile, err = os.OpenFile("disk_throughput.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	return nil
}
func startLogWriter() {
	logWriterMutex.Lock()
	if logWriterStarted {
		logWriterMutex.Unlock()
		return
	}
	logWriterStarted = true
	logWriterMutex.Unlock()
	
	logChannel = make(chan string, 10000) // Larger buffer for high-throughput scenarios
	logWriterWaitGroup.Add(1)
	go func() {
		defer logWriterWaitGroup.Done()
		
		if err := initLogFile(); err != nil {
			// Drain channel on error
			for range logChannel {
				atomic.AddInt64(&droppedLogs, 1)
			}
			return
		}
		
		// Batch write buffer for better performance
		batch := make([]string, 0, 100)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		
		flushBatch := func() {
			if len(batch) > 0 && logFile != nil {
				for _, msg := range batch {
					timestamp := time.Now().Format("2006/01/02 15:04:05")
					fileMessage := fmt.Sprintf("%s %s\n", timestamp, msg)
					logFile.WriteString(fileMessage)
				}
				logFile.Sync()
				batch = batch[:0]
			}
		}
		
		for {
			select {
			case msg, ok := <-logChannel:
				if !ok {
					flushBatch()
					return
				}
				batch = append(batch, msg)
				if len(batch) >= 100 {
					flushBatch()
				}
			case <-ticker.C:
				flushBatch()
			}
		}
	}()
}
func TrackDiskRead(bytes int64) {
	atomic.AddInt64(&globalDiskTracker.readBytes, bytes)
	atomic.AddInt64(&globalDiskTracker.readOps, 1)
}
func TrackDiskWrite(bytes int64) {
	atomic.AddInt64(&globalDiskTracker.writeBytes, bytes)
	atomic.AddInt64(&globalDiskTracker.writeOps, 1)
}
func GetDiskThroughput() string {
	readBytes := atomic.LoadInt64(&globalDiskTracker.readBytes)
	writeBytes := atomic.LoadInt64(&globalDiskTracker.writeBytes)
	readOps := atomic.LoadInt64(&globalDiskTracker.readOps)
	writeOps := atomic.LoadInt64(&globalDiskTracker.writeOps)
	globalDiskTracker.mu.RLock()
	elapsedTotal := time.Since(globalDiskTracker.startTime).Seconds()
	elapsedSinceLog := time.Since(globalDiskTracker.lastLogTime).Seconds()
	globalDiskTracker.mu.RUnlock()
	if elapsedSinceLog < 0.001 {
		elapsedSinceLog = 0.001
	}
	if elapsedTotal < 0.001 {
		elapsedTotal = 0.001
	}
	readMBps := float64(readBytes) / (1024 * 1024) / elapsedTotal
	writeMBps := float64(writeBytes) / (1024 * 1024) / elapsedTotal
	totalMBps := readMBps + writeMBps
	return fmt.Sprintf("Disk throughput: %.2f MB/s (R: %.2f MB/s, W: %.2f MB/s) | Ops: %d reads, %d writes", 
		totalMBps, readMBps, writeMBps, readOps, writeOps)
}
func LogDiskThroughput(function string) {
	// Ensure log writer is started
	startLogWriter()
	
	// Update timestamp without blocking
	globalDiskTracker.mu.Lock()
	globalDiskTracker.lastLogTime = time.Now()
	globalDiskTracker.mu.Unlock()
	
	// Get throughput stats (fast, read-only atomic operations)
	throughput := GetDiskThroughput()
	logMessage := fmt.Sprintf("[%s] %s", function, throughput)
	
	// Non-blocking send to log channel
	select {
	case logChannel <- logMessage:
		// Successfully queued for async logging
	default:
		// Channel full, increment dropped counter
		atomic.AddInt64(&droppedLogs, 1)
	}
}

// LogDiskThroughputAsync is a fire-and-forget version that runs in a goroutine
func LogDiskThroughputAsync(function string) {
	go LogDiskThroughput(function)
}

// GetDroppedLogCount returns the number of log messages that were dropped due to buffer overflow
func GetDroppedLogCount() int64 {
	return atomic.LoadInt64(&droppedLogs)
}
func ResetDiskTracker() {
	atomic.StoreInt64(&globalDiskTracker.readBytes, 0)
	atomic.StoreInt64(&globalDiskTracker.writeBytes, 0)
	atomic.StoreInt64(&globalDiskTracker.readOps, 0)
	atomic.StoreInt64(&globalDiskTracker.writeOps, 0)
	globalDiskTracker.mu.Lock()
	globalDiskTracker.startTime = time.Now()
	globalDiskTracker.lastLogTime = time.Now()
	globalDiskTracker.mu.Unlock()
}

// ShutdownDiskLogger gracefully shuts down the disk logger, flushing all pending logs
func ShutdownDiskLogger() {
	logWriterMutex.Lock()
	if !logWriterStarted {
		logWriterMutex.Unlock()
		return
	}
	logWriterMutex.Unlock()
	
	// Close the channel to signal shutdown
	if logChannel != nil {
		close(logChannel)
	}
	
	// Wait for the writer goroutine to finish
	logWriterWaitGroup.Wait()
	
	// Close the log file
	if logFile != nil {
		logFile.Close()
		logFile = nil
	}
}
