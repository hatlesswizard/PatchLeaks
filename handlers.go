package main
import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)
var templates *template.Template
func init() {
	funcMap := template.FuncMap{
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,
		"contains":  strings.Contains,
		"toLower":   strings.ToLower,
		"toUpper":   strings.ToUpper,
		"length": func(v interface{}) int {
			switch val := v.(type) {
			case map[string]interface{}:
				return len(val)
			case map[string]AnalysisResult:
				return len(val)
			case []interface{}:
				return len(val)
			case []string:
				return len(val)
			default:
				return 0
			}
		},
		"add": func(a, b int) int {
			return a + b
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"gt": func(a, b int) bool {
			return a > b
		},
		"lt": func(a, b int) bool {
			return a < b
		},
		"le": func(a, b int) bool {
			return a <= b
		},
		"ge": func(a, b int) bool {
			return a >= b
		},
		"mul": func(a, b float64) float64 {
			return a * b
		},
		"div": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"float64": func(v interface{}) float64 {
			switch val := v.(type) {
			case int:
				return float64(val)
			case int32:
				return float64(val)
			case int64:
				return float64(val)
			case float64:
				return val
			case float32:
				return float64(val)
			default:
				return 0
			}
		},
		"json": func(v interface{}) string {
			b, err := json.Marshal(v)
			if err != nil {
				return "{}"
			}
			return string(b)
		},
	}
	templates = template.New("").Funcs(funcMap)
	templateFiles := []string{
		"templates/index.html",
		"templates/ai_settings.html",
		"templates/manage_products.html",
		"templates/reports.html",
		"templates/library.html",
		"templates/products.html",
		"templates/folder.html",
		"templates/analysis.html",
		"templates/dashboard.html",
	}
	var parseErrors []string
	for _, tmplFile := range templateFiles {
		_, err := templates.ParseFiles(tmplFile)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("  [ERROR] %s: %v", tmplFile, err))
		} else {
		}
	}
	if len(parseErrors) > 0 {
		for _, _ = range parseErrors {
		}
		templates = nil
	} else {
	}
}
func templatesLoaded() bool {
	return templates != nil
}
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if !templatesLoaded() {
		http.Error(w, `Templates not loaded. Please convert templates from Jinja2 to Go syntax.
See TEMPLATE_EXAMPLES.md for conversion guide.
Example: Replace {% for item in items %} with {{range .Items}}`, http.StatusInternalServerError)
		return
	}
	if err := templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		http.Error(w, fmt.Sprintf("Template execution error: %v", err), http.StatusInternalServerError)
		return
	}
}
func viewAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	analysisID := vars["id"]
	if !isValidUUID(analysisID) {
		http.Error(w, "Invalid analysis ID", http.StatusNotFound)
		return
	}
	analysisPath := filepath.Join("saved_analyses", analysisID+".json")
	data, err := TrackedReadFile(analysisPath)
	if err != nil {
		http.Error(w, "Analysis not found", http.StatusNotFound)
		return
	}
	var analysis Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		http.Error(w, "Invalid analysis data", http.StatusInternalServerError)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 5 || perPage > 100 {
		perPage = 20
	}
	filterType := r.URL.Query().Get("filter")
	if filterType == "" {
		filterType = "all"
	}
	paginatedResults := analysis.Results
	var pagination *Pagination
	type IndexedResult struct {
		Index    int
		Filename string
		Result   AnalysisResult
	}
	indexedResults := []IndexedResult{}
	idx := 0
	var sortedKeys []string
	for filename := range paginatedResults {
		sortedKeys = append(sortedKeys, filename)
	}
	sort.Strings(sortedKeys)
	for _, filename := range sortedKeys {
		indexedResults = append(indexedResults, IndexedResult{
			Index:    idx,
			Filename: filename,
			Result:   paginatedResults[filename],
		})
		idx++
	}
	templateData := struct {
		Analysis           Analysis
		PaginatedResults   map[string]AnalysisResult
		IndexedResults     []IndexedResult
		Pagination         *Pagination
		TotalOriginalFiles int
		IsShared           bool
		AnalysisID         string
		AnalysisURL        string
		Status             string
	}{
		Analysis:           analysis,
		PaginatedResults:   paginatedResults,
		IndexedResults:     indexedResults,
		Pagination:         pagination,
		TotalOriginalFiles: len(analysis.Results),
		IsShared:           true,
		AnalysisID:         analysisID,
		AnalysisURL:        fmt.Sprintf("http://%s/analysis/%s", r.Host, analysisID),
		Status:             analysis.Meta.Status,
	}
	if err := templates.ExecuteTemplate(w, "analysis.html", templateData); err != nil {
	}
}
func saveAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	var requestData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON data"})
		return
	}
	analysisID := uuid.New().String()
	aiService, _ := requestData["ai_service"].(string)
	aiModel, _ := requestData["ai_model"].(string)
	enableAI, _ := requestData["enable_ai"].(bool)
	if enableAI && config != nil {
		aiService = config.Service
		if svcConfig, ok := config.GetServiceConfig(aiService); ok {
			aiModel = svcConfig["model"].(string)
		}
	}
	analysis := Analysis{
		Meta: AnalysisMeta{
			CreatedAt: time.Now(),
			Source:    validateInput(requestData["source"], 20),
			AIEnabled: enableAI,
			AIService: aiService,
			AIModel:   aiModel,
			Status:    "completed",
		},
		Results: make(map[string]AnalysisResult),
	}
	if params, ok := requestData["params"].(map[string]interface{}); ok {
		analysis.Meta.Params = params
	}
	if results, ok := requestData["results"].(map[string]interface{}); ok {
		for k, v := range results {
			if resultMap, ok := v.(map[string]interface{}); ok {
				result := AnalysisResult{}
				if context, ok := resultMap["context"].([]interface{}); ok {
					for _, line := range context {
						if str, ok := line.(string); ok {
							result.Context = append(result.Context, str)
						}
					}
				}
				if aiResp, ok := resultMap["ai_response"].(string); ok {
					result.AIResponse = aiResp
				}
				if vulnStatus, ok := resultMap["vulnerability_status"].(string); ok {
					result.VulnerabilityStatus = vulnStatus
				}
				if severity, ok := resultMap["vuln_severity"].(string); ok {
					result.VulnSeverity = severity
				}
				analysis.Results[k] = result
			}
		}
	}
	analysisPath := filepath.Join("saved_analyses", analysisID+".json")
	data, _ := json.MarshalIndent(analysis, "", "  ")
	if err := TrackedWriteFile(analysisPath, data, 0644); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save analysis"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"id": analysisID})
}
func deleteAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	analysisID := vars["id"]
	if !isValidUUID(analysisID) {
		http.Redirect(w, r, "/reports", http.StatusSeeOther)
		return
	}
	analysisPath := filepath.Join("saved_analyses", analysisID+".json")
	if err := os.Remove(analysisPath); err != nil {
	}
	http.Redirect(w, r, "/reports", http.StatusSeeOther)
}
func productsHandler(w http.ResponseWriter, r *http.Request) {
	productsData := loadProducts()
	productsList := make([]string, 0, len(productsData))
	for name := range productsData {
		productsList = append(productsList, name)
	}
	sort.Strings(productsList)
	if r.Method == "POST" {
		r.ParseForm()
		product := validateInput(r.FormValue("product"), 100)
		oldVersion := validateInput(r.FormValue("old_version"), 50)
		newVersion := validateInput(r.FormValue("new_version"), 50)
		extension := validateInput(r.FormValue("extension"), 10)
		enableAI := r.FormValue("enable_ai")
		specialKeywords := validateInput(r.FormValue("special_keywords"), 500)
		cveIDs := validateInput(r.FormValue("cve_ids"), 200)
		if product == "" || oldVersion == "" || newVersion == "" {
			http.Redirect(w, r, "/products", http.StatusSeeOther)
			return
		}
		params := map[string]interface{}{
			"product":          product,
			"old_version":      oldVersion,
			"new_version":      newVersion,
			"extension":        extension,
			"enable_ai":        enableAI,
			"special_keywords": specialKeywords,
			"cve_ids":          cveIDs,
		}
		analysisID := createNewAnalysisRecord(params, "products", enableAI == "on")
		go runAnalysisBackground(analysisID, params, "products")
		http.Redirect(w, r, fmt.Sprintf("/analysis/%s", analysisID), http.StatusSeeOther)
		return
	}
	data := struct {
		Products        []string
		AnalyzedResults map[string]AnalysisResult
		Product         string
		OldVersion      string
		NewVersion      string
		Extension       string
		SpecialKeywords string
		CVEIDs          string
		EnableAI        string
		FlashMessages   []FlashMessage
		Error           string
	}{
		Products:        productsList,
		AnalyzedResults: make(map[string]AnalysisResult),
		Product:         "",
		OldVersion:      "",
		NewVersion:      "",
		Extension:       "",
		SpecialKeywords: "",
		CVEIDs:          "",
		EnableAI:        "",
		FlashMessages:   []FlashMessage{},
		Error:           "",
	}
	if err := templates.ExecuteTemplate(w, "products.html", data); err != nil {
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
		return
	}
}
func folderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		oldFolder := validateInput(r.FormValue("old_folder"), 500)
		newFolder := validateInput(r.FormValue("new_folder"), 500)
		extension := validateInput(r.FormValue("extension"), 10)
		enableAI := r.FormValue("enable_ai")
		specialKeywords := validateInput(r.FormValue("special_keywords"), 500)
		cveIDs := validateInput(r.FormValue("cve_ids"), 200)
		if oldFolder == "" || newFolder == "" {
			http.Redirect(w, r, "/folder", http.StatusSeeOther)
			return
		}
		params := map[string]interface{}{
			"old_folder":       oldFolder,
			"new_folder":       newFolder,
			"extension":        extension,
			"enable_ai":        enableAI,
			"special_keywords": specialKeywords,
			"cve_ids":          cveIDs,
		}
		analysisID := createNewAnalysisRecord(params, "folder", enableAI == "on")
		go runAnalysisBackground(analysisID, params, "folder")
		http.Redirect(w, r, fmt.Sprintf("/analysis/%s", analysisID), http.StatusSeeOther)
		return
	}
	data := struct {
		AnalyzedResults map[string]AnalysisResult
		OldFolder       string
		NewFolder       string
		Extension       string
		SpecialKeywords string
		CVEIDs          string
		EnableAI        string
		FlashMessages   []FlashMessage
		Error           string
	}{
		AnalyzedResults: make(map[string]AnalysisResult),
		OldFolder:       "",
		NewFolder:       "",
		Extension:       "",
		SpecialKeywords: "",
		CVEIDs:          "",
		EnableAI:        "",
		FlashMessages:   []FlashMessage{},
		Error:           "",
	}
	if err := templates.ExecuteTemplate(w, "folder.html", data); err != nil {
	}
}
func reportsHandler(w http.ResponseWriter, r *http.Request) {
	reports := loadAllAnalyses()
	for i := range reports {
		reports[i].VulnCount = countVulnerabilities(reports[i].Results)
	}
	data := struct {
		Reports       []Analysis
		FlashMessages []FlashMessage
	}{
		Reports:       reports,
		FlashMessages: []FlashMessage{},
	}
	if err := templates.ExecuteTemplate(w, "reports.html", data); err != nil {
	}
}
func manageProductsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		productName := validateInput(r.FormValue("product_name"), 100)
		repoURL := validateInput(r.FormValue("repo_url"), 200)
		if productName == "" || repoURL == "" || !validateURL(repoURL) {
			products := loadProducts()
			data := struct {
				Products      map[string]Product
				Error         string
				FlashMessages []FlashMessage
			}{
				Products:      products,
				Error:         "Invalid product name or repository URL",
				FlashMessages: []FlashMessage{},
			}
			templates.ExecuteTemplate(w, "manage_products.html", data)
			return
		}
		products := loadProducts()
		if _, exists := products[productName]; exists {
			data := struct {
				Products      map[string]Product
				Error         string
				FlashMessages []FlashMessage
			}{
				Products:      products,
				Error:         "Product already exists",
				FlashMessages: []FlashMessage{},
			}
			templates.ExecuteTemplate(w, "manage_products.html", data)
			return
		}
		products[productName] = Product{
			RepoURL:  repoURL,
			Versions: []string{},
		}
		saveProducts(products)
		http.Redirect(w, r, "/manage-products", http.StatusSeeOther)
		return
	}
	products := loadProducts()
	data := struct {
		Products      map[string]Product
		Error         string
		FlashMessages []FlashMessage
	}{
		Products:      products,
		Error:         "",
		FlashMessages: []FlashMessage{},
	}
	if err := templates.ExecuteTemplate(w, "manage_products.html", data); err != nil {
	}
}
func deleteProductHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	productName := validateInput(vars["name"], 100)
	if productName == "" {
		http.Redirect(w, r, "/manage-products", http.StatusSeeOther)
		return
	}
	products := loadProducts()
	delete(products, productName)
	saveProducts(products)
	http.Redirect(w, r, "/manage-products", http.StatusSeeOther)
}
func getVersionsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	product := validateInput(vars["product"], 100)
	if product == "" {
		respondJSON(w, http.StatusOK, []string{})
		return
	}
	products := loadProducts()
	if productData, exists := products[product]; exists {
		if validateURL(productData.RepoURL) {
			versions := getGitHubVersions(productData.RepoURL)
			respondJSON(w, http.StatusOK, versions)
			return
		} else {
		}
	} else {
	}
	respondJSON(w, http.StatusOK, []string{})
}
func aiSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		aiService := validateInput(r.FormValue("ai_service"), 50)
		temperature, _ := strconv.ParseFloat(r.FormValue("temperature"), 64)
		numCtx, _ := strconv.Atoi(r.FormValue("num_ctx"))
		if temperature < 0 {
			temperature = 0
		} else if temperature > 2 {
			temperature = 2
		}
		if numCtx < 1024 {
			numCtx = 1024
		} else if numCtx > 32768 {
			numCtx = 32768
		}
		
		
		newParameters := make(map[string]interface{})
		if config != nil && config.Parameters != nil {
			for k, v := range config.Parameters {
				newParameters[k] = v
			}
		}
		
		newParameters["temperature"] = temperature
		newParameters["num_ctx"] = numCtx
		newParameters["enable_context_analysis"] = r.FormValue("enable_context_analysis") == "on"
		newConfig := &Config{
			Service: aiService,
			Ollama: map[string]interface{}{
				"url":   validateInput(r.FormValue("ollama_url"), 200),
				"model": validateInput(r.FormValue("ollama_model"), 100),
			},
			OpenAI: map[string]interface{}{
				"key":      validateInput(r.FormValue("openai_key"), 200),
				"model":    validateInput(r.FormValue("openai_model"), 100),
				"base_url": validateInput(r.FormValue("openai_url"), 200),
			},
			DeepSeek: map[string]interface{}{
				"key":      validateInput(r.FormValue("deepseek_key"), 200),
				"model":    validateInput(r.FormValue("deepseek_model"), 100),
				"base_url": validateInput(r.FormValue("deepseek_url"), 200),
			},
			Claude: map[string]interface{}{
				"key":      validateInput(r.FormValue("claude_key"), 200),
				"model":    validateInput(r.FormValue("claude_model"), 100),
				"base_url": validateInput(r.FormValue("claude_url"), 200),
			},
			NVD: map[string]interface{}{
				"api_key": validateInput(r.FormValue("nvd_api_key"), 200),
			},
			Parameters: newParameters,
			Prompts: map[string]string{
				"main_analysis": validatePrompt(r.FormValue("main_analysis_prompt"), 5000),
				"cve_analysis":  validatePrompt(r.FormValue("cve_analysis_prompt"), 5000),
				"cve_writeup":   validatePrompt(r.FormValue("cve_writeup_prompt"), 10000),
			},
		}
		if err := newConfig.Save(); err != nil {
		} else {
			
			reloadedConfig, err := LoadConfig()
			if err != nil {
			} else {
				config = reloadedConfig
			}
		}
		http.Redirect(w, r, "/ai-settings", http.StatusSeeOther)
		return
	}
	data := struct {
		Config        *Config
		FlashMessages []FlashMessage
	}{
		Config:        config,
		FlashMessages: []FlashMessage{},
	}
	if err := templates.ExecuteTemplate(w, "ai_settings.html", data); err != nil {
	}
}
func resetPromptsHandler(w http.ResponseWriter, r *http.Request) {
	if config != nil {
		config.Prompts = DefaultPrompts()
		config.Save()
	}
	http.Redirect(w, r, "/ai-settings", http.StatusSeeOther)
}
func libraryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		name := validateInput(r.FormValue("name"), 100)
		repoURL := validateInput(r.FormValue("repo_url"), 200)
		aiService := validateInput(r.FormValue("ai_service"), 50)
		cpe := validateInput(r.FormValue("cpe"), 200)
		if name == "" || repoURL == "" || !validateURL(repoURL) {
			http.Redirect(w, r, "/library", http.StatusSeeOther)
			return
		}
		addLibraryRepo(name, repoURL, aiService, cpe)
		http.Redirect(w, r, "/library", http.StatusSeeOther)
		return
	}
	library := loadLibrary()
	data := struct {
		LibraryRepos  []LibraryRepo
		FlashMessages []FlashMessage
	}{
		LibraryRepos:  library,
		FlashMessages: []FlashMessage{},
	}
	if err := templates.ExecuteTemplate(w, "library.html", data); err != nil {
	}
}
func deleteLibraryRepoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	repoID := vars["id"]
	if isValidUUID(repoID) {
		removeLibraryRepo(repoID)
	}
	http.Redirect(w, r, "/library", http.StatusSeeOther)
}
func toggleLibraryRepoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	repoID := vars["id"]
	if isValidUUID(repoID) {
		toggleLibraryAutoScan(repoID)
	}
	http.Redirect(w, r, "/library", http.StatusSeeOther)
}
func checkVersionsNowHandler(w http.ResponseWriter, r *http.Request) {
	go checkForNewVersions()
	http.Redirect(w, r, "/library", http.StatusSeeOther)
}
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if !templatesLoaded() {
		http.Error(w, "Templates not loaded", http.StatusInternalServerError)
		return
	}
	stats, err := GetDashboardStats()
	if err != nil {
		http.Error(w, "Error loading dashboard", http.StatusInternalServerError)
		return
	}
	data := struct {
		Stats         DashboardStats
		FlashMessages []FlashMessage
	}{
		Stats:         *stats,
		FlashMessages: []FlashMessage{},
	}
	if err := templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		if err.Error() != "write tcp" && !strings.Contains(err.Error(), "broken pipe") {
		}
		return
	}
}
func dashboardAPIHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := GetDashboardStats()
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to load stats"})
		return
	}
	respondJSON(w, http.StatusOK, stats)
}
func respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}
