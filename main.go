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
	config            *Config
	sessionStore      *sessions.CookieStore
	basicAuthUsername string
	basicAuthPassword string
	
	port      = flag.Int("p", 0, "Port to run the server on (default: random free port)")
	host      = flag.String("host", DefaultHost, "Host address to bind to")
	aiThreads = flag.Int("t", 1, "Number of threads for AI analysis (default: 1)")
)

func main() {
	flag.Parse()

	basicAuthUsername = generateRandomMD5()
	basicAuthPassword = generateRandomMD5()

	
	serverPort := *port
	if serverPort == 0 {
		serverPort = findFreePort()
		fmt.Printf("🔍 No port specified, using random free port: %d\n", serverPort)
	}

	initializeDirectories()

	
	var err error
	config, err = LoadConfig()
	if err != nil {
		log.Printf("Warning: Could not load config, using defaults: %v", err)
		config = DefaultConfig()
	}

	sessionStore = sessions.NewCookieStore([]byte(generateRandomMD5()))

	
	router := setupRouter()

	printBanner(basicAuthUsername, basicAuthPassword, *host, serverPort, *aiThreads)

	
	go startScheduler()

	addr := fmt.Sprintf("%s:%d", *host, serverPort)
	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
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

	productsFile := filepath.Join("products", "products.json")
	if _, err := os.Stat(productsFile); os.IsNotExist(err) {
		if err := os.WriteFile(productsFile, []byte("{}"), 0644); err != nil {
			log.Printf("Warning: Could not create products.json: %v", err)
		}
	}

	libraryFile := filepath.Join("products", "library.json")
	if _, err := os.Stat(libraryFile); os.IsNotExist(err) {
		if err := os.WriteFile(libraryFile, []byte("[]"), 0644); err != nil {
			log.Printf("Warning: Could not create library.json: %v", err)
		}
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

