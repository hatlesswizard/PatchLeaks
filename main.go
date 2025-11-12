package main
import (
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)
const (
	DefaultHost = "127.0.0.1"
)
var (
	config            *Config
	sessionStore      *sessions.CookieStore
	basicAuthUsername string
	basicAuthPassword string
	port              = flag.Int("p", 0, "Port to run the server on (default: random free port)")
	host              = flag.String("host", DefaultHost, "Host address to bind to")
	aiThreads         = flag.Int("t", 1, "Number of threads for AI analysis (default: 1)")
	testRealWorld     = flag.Bool("test-real-world", false, "Run real-world tests instead of starting server")
	testLanguages     = flag.String("language", "", "Comma-separated list of languages to test (php,javascript,python)")
)
func main() {
	flag.Parse()
	maxCPUPercent := 50.0 
	InitCPUThrottler(maxCPUPercent)
	GetBuiltinDetector()
	
	// Setup graceful shutdown
	setupGracefulShutdown()
	
	if *testRealWorld {
		initializeDirectories()
		var languages []string
		if *testLanguages != "" {
			languages = strings.Split(*testLanguages, ",")
			for i, lang := range languages {
				languages[i] = strings.TrimSpace(lang)
			}
		}
		if err := RunRealWorldTests(languages); err != nil {
			ShutdownDiskLogger() // Ensure logs are flushed before exit
			os.Exit(1)
		}
		ShutdownDiskLogger() // Ensure logs are flushed before exit
		os.Exit(0)
	}
	basicAuthUsername = generateRandomMD5()
	basicAuthPassword = generateRandomMD5()
	serverPort := *port
	if serverPort == 0 {
		serverPort = findFreePort()
	}
	initializeDirectories()
	var err error
	config, err = LoadConfig()
	if err != nil {
		config = DefaultConfig()
	}
	sessionStore = sessions.NewCookieStore([]byte(generateRandomMD5()))
	router := setupRouter()
	printBanner(basicAuthUsername, basicAuthPassword, *host, serverPort, *aiThreads)
	go startScheduler()
	go func() {
		_, err := GetDashboardStats()
		if err != nil {
		} else {
		}
	}()
	
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
		}
	}()
	addr := fmt.Sprintf("%s:%d", *host, serverPort)
	if err := http.ListenAndServe(addr, router); err != nil {
		ShutdownDiskLogger() // Ensure logs are flushed before exit
		os.Exit(1)
	}
}

// setupGracefulShutdown sets up signal handlers for graceful shutdown
func setupGracefulShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		fmt.Println("\nReceived shutdown signal, flushing logs...")
		ShutdownDiskLogger()
		os.Exit(0)
	}()
}
func setupRouter() *mux.Router {
	r := mux.NewRouter()
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	r.HandleFunc("/", indexHandler).Methods("GET")
	r.HandleFunc("/analysis/{id}", viewAnalysisHandler).Methods("GET")
	r.HandleFunc("/get_versions/{product}", getVersionsHandler).Methods("GET")
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(basicAuthMiddleware)
	protected.Use(rateLimitMiddleware)
	r.HandleFunc("/save-analysis", saveAnalysisHandler).Methods("POST")
	protected.HandleFunc("/delete-analysis/{id}", deleteAnalysisHandler).Methods("POST")
	r.HandleFunc("/manage-products", manageProductsHandler).Methods("GET", "POST")
	protected.HandleFunc("/delete-product/{name}", deleteProductHandler).Methods("GET")
	r.HandleFunc("/products", productsHandler).Methods("GET", "POST")
	r.HandleFunc("/folder", folderHandler).Methods("GET", "POST")
	r.HandleFunc("/library", libraryHandler).Methods("GET", "POST")
	protected.HandleFunc("/library/delete/{id}", deleteLibraryRepoHandler).Methods("POST")
	protected.HandleFunc("/library/toggle/{id}", toggleLibraryRepoHandler).Methods("POST")
	protected.HandleFunc("/library/check-now", checkVersionsNowHandler).Methods("POST")
	protected.HandleFunc("/ai-settings", aiSettingsHandler).Methods("GET", "POST")
	protected.HandleFunc("/reset-prompts", resetPromptsHandler).Methods("POST")
	r.HandleFunc("/reports", reportsHandler).Methods("GET")
	r.HandleFunc("/dashboard", dashboardHandler).Methods("GET")
	r.HandleFunc("/api/dashboard/stats", dashboardAPIHandler).Methods("GET")
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
		os.Exit(1)
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
			os.Exit(1)
		}
		TrackDiskWrite(100)
	}
	productsFile := filepath.Join("products", "products.json")
	if _, err := os.Stat(productsFile); os.IsNotExist(err) {
		if err := TrackedWriteFile(productsFile, []byte("{}"), 0644); err != nil {
		}
		TrackDiskWrite(2)
	}
	libraryFile := filepath.Join("products", "library.json")
	if _, err := os.Stat(libraryFile); os.IsNotExist(err) {
		if err := TrackedWriteFile(libraryFile, []byte("[]"), 0644); err != nil {
		}
		TrackDiskWrite(2)
	}
}
func printBanner(username, password, host string, port, aiThreads int) {
	serverURL := fmt.Sprintf("http://%s:%d", host, port)
	aiThreadsStr := fmt.Sprintf("%d", aiThreads)
	maxWidth := 67
	urlLine := fmt.Sprintf("║  Server URL:  %s", serverURL)
	threadsLine := fmt.Sprintf("║  AI Threads:  %s", aiThreadsStr)
	for len(urlLine) < maxWidth {
		urlLine += " "
	}
	urlLine += "║"
	for len(threadsLine) < maxWidth {
		threadsLine += " "
	}
	threadsLine += "║"
	banner := fmt.Sprintf(`
╔════════════════════════════════════════════════════════════════╗
║                      PatchLeaks Started                        ║
╠════════════════════════════════════════════════════════════════╣
%s
%s
║                                                                ║
║  Basic Authentication Credentials:                             ║
║  ┌────────────────────────────────────────────────────────┐    ║
║  │ Username: %-32s │           │    ║
║  │ Password: %-32s │           |    ║
║  └────────────────────────────────────────────────────────┘    ║
║                                                                ║
║  IMPORTANT: Save these credentials!                            ║
║  They are randomly generated each time the app starts.         ║
╚════════════════════════════════════════════════════════════════╝
`, urlLine, threadsLine, username, password)
	fmt.Println(banner)
}
func init() {
	rand.Seed(time.Now().UnixNano())
}
