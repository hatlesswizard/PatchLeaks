package main

import (
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

const (
	DefaultHost = "127.0.0.1"
)

var (
	// Global configuration
	config            *Config
	sessionStore      *sessions.CookieStore
	basicAuthUsername string
	basicAuthPassword string
	
	// Command line flags
	port      = flag.Int("p", 0, "Port to run the server on (default: random free port)")
	host      = flag.String("host", DefaultHost, "Host address to bind to")
	aiThreads = flag.Int("t", 1, "Number of threads for AI analysis (default: 1)")
)

func main() {
	flag.Parse()

	// Generate random MD5 credentials
	basicAuthUsername = generateRandomMD5()
	basicAuthPassword = generateRandomMD5()

	// Determine port
	serverPort := *port
	if serverPort == 0 {
		serverPort = findFreePort()
		fmt.Printf("🔍 No port specified, using random free port: %d\n", serverPort)
	}

	// Initialize directories
	initializeDirectories()

	// Load configuration
	var err error
	config, err = LoadConfig()
	if err != nil {
		log.Printf("Warning: Could not load config, using defaults: %v", err)
		config = DefaultConfig()
	}

	// Initialize session store
	sessionStore = sessions.NewCookieStore([]byte(generateRandomMD5()))

	// Setup router
	router := setupRouter()

	// Print banner
	printBanner(basicAuthUsername, basicAuthPassword, *host, serverPort, *aiThreads)

	// Start background scheduler
	go startScheduler()

	// Start server
	addr := fmt.Sprintf("%s:%d", *host, serverPort)
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func setupRouter() *mux.Router {
	r := mux.NewRouter()

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Public routes
	r.HandleFunc("/", indexHandler).Methods("GET")
	r.HandleFunc("/analysis/{id}", viewAnalysisHandler).Methods("GET")
	r.HandleFunc("/get_versions/{product}", getVersionsHandler).Methods("GET") // Public for AJAX calls

	// Protected routes with authentication
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(basicAuthMiddleware)
	protected.Use(rateLimitMiddleware)

	// Analysis routes
	protected.HandleFunc("/save-analysis", saveAnalysisHandler).Methods("POST")
	protected.HandleFunc("/delete-analysis/{id}", deleteAnalysisHandler).Methods("POST")

	// Product management routes
	protected.HandleFunc("/manage-products", manageProductsHandler).Methods("GET", "POST")
	protected.HandleFunc("/delete-product/{name}", deleteProductHandler).Methods("GET")

	// Analysis execution routes
	protected.HandleFunc("/products", productsHandler).Methods("GET", "POST")
	protected.HandleFunc("/folder", folderHandler).Methods("GET", "POST")

	// Library management routes
	protected.HandleFunc("/library", libraryHandler).Methods("GET", "POST")
	protected.HandleFunc("/library/delete/{id}", deleteLibraryRepoHandler).Methods("POST")
	protected.HandleFunc("/library/toggle/{id}", toggleLibraryRepoHandler).Methods("POST")
	protected.HandleFunc("/library/check-now", checkVersionsNowHandler).Methods("POST")
	
	// AI Settings routes
	protected.HandleFunc("/ai-settings", aiSettingsHandler).Methods("GET", "POST")
	protected.HandleFunc("/reset-prompts", resetPromptsHandler).Methods("POST")

	// Reports routes
	protected.HandleFunc("/reports", reportsHandler).Methods("GET")

	// AI Benchmark routes
	protected.HandleFunc("/ai-benchmark", aiBenchmarkHandler).Methods("GET", "POST")
	protected.HandleFunc("/benchmark-results/{id}", benchmarkResultsHandler).Methods("GET")
	protected.HandleFunc("/benchmark-status/{id}", benchmarkStatusHandler).Methods("GET")
	protected.HandleFunc("/delete-benchmark/{id}", deleteBenchmarkHandler).Methods("POST")

	return r
}

func generateRandomMD5() string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	hash := md5.Sum(randBytes)
	return hex.EncodeToString(hash[:])
}

func findFreePort() int {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func initializeDirectories() {
	dirs := []string{
		"products",
		"saved_analyses",
		"logs",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	// Create products.json if it doesn't exist
	productsFile := filepath.Join("products", "products.json")
	if _, err := os.Stat(productsFile); os.IsNotExist(err) {
		if err := os.WriteFile(productsFile, []byte("{}"), 0644); err != nil {
			log.Printf("Warning: Could not create products.json: %v", err)
		}
	}

	// Create library.json if it doesn't exist
	libraryFile := filepath.Join("products", "library.json")
	if _, err := os.Stat(libraryFile); os.IsNotExist(err) {
		if err := os.WriteFile(libraryFile, []byte("[]"), 0644); err != nil {
			log.Printf("Warning: Could not create library.json: %v", err)
		}
	}
}

func printBanner(username, password, host string, port, aiThreads int) {
	banner := fmt.Sprintf(`
╔════════════════════════════════════════════════════════════════╗
║                      PatchLeaks Started                        ║
╠════════════════════════════════════════════════════════════════╣
║  Server URL:  http://%s:%-5d                         
║  AI Threads:  %-5d                                            
║                                                                ║
║  Basic Authentication Credentials:                             ║
║  ┌────────────────────────────────────────────────────────┐   ║
║  │ Username: %-32s │   ║
║  │ Password: %-32s │   ║
║  └────────────────────────────────────────────────────────┘   ║
║                                                                ║
║  ⚠️  IMPORTANT: Save these credentials!                        ║
║  They are randomly generated each time the app starts.         ║
╚════════════════════════════════════════════════════════════════╝
`, host, port, aiThreads, username, password)

	fmt.Println(banner)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

