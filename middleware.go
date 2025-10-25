package main

import (
	"encoding/base64"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Rate limiter structure
type rateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
}

type visitor struct {
	lastSeen time.Time
	count    int
}

var (
	limiter = &rateLimiter{
		visitors: make(map[string]*visitor),
	}
	
	// Rate limit configuration
	requestsPerMinute = 50
	cleanupInterval   = time.Minute * 5
)

func init() {
	// Start cleanup goroutine
	go cleanupVisitors()
}

// Basic auth middleware
func basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		
		if auth == "" {
			requestAuth(w)
			return
		}

		// Parse authorization header
		const prefix = "Basic "
		if !strings.HasPrefix(auth, prefix) {
			requestAuth(w)
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
		if err != nil {
			requestAuth(w)
			return
		}

		credentials := strings.SplitN(string(decoded), ":", 2)
		if len(credentials) != 2 {
			requestAuth(w)
			return
		}

		username, password := credentials[0], credentials[1]
		if username != basicAuthUsername || password != basicAuthPassword {
			requestAuth(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func requestAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Login Required"`)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("Authentication required"))
}

// Rate limit middleware
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		
		limiter.mu.Lock()
		v, exists := limiter.visitors[ip]
		if !exists {
			limiter.visitors[ip] = &visitor{
				lastSeen: time.Now(),
				count:    1,
			}
			limiter.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		// Reset count if last seen was over a minute ago
		if time.Since(v.lastSeen) > time.Minute {
			v.count = 1
			v.lastSeen = time.Now()
			limiter.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		// Check rate limit
		if v.count >= requestsPerMinute {
			limiter.mu.Unlock()
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		v.count++
		v.lastSeen = time.Now()
		limiter.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

func getIP(r *http.Request) string {
	// Try X-Forwarded-For header first
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

func cleanupVisitors() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		limiter.mu.Lock()
		for ip, v := range limiter.visitors {
			if time.Since(v.lastSeen) > time.Hour {
				delete(limiter.visitors, ip)
			}
		}
		limiter.mu.Unlock()
	}
}

// CORS middleware (if needed)
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Logging middleware
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapped, r)
		
		// Log request
		duration := time.Since(start)
		log.Printf("%s %s %d %v", r.Method, r.URL.Path, wrapped.statusCode, duration)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

