package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	MaxRetryAttempts = 3
	RateLimitBackoff = 2
	MaxBackoffTime   = 60
)

type AIServiceClient struct {
	config  *Config
	service string
	timeout time.Duration
}

func NewAIServiceClient(config *Config) *AIServiceClient {
	return &AIServiceClient{
		config:  config,
		service: config.Service,
		timeout: 0,
	}
}

func (client *AIServiceClient) GenerateResponse(prompt string) string {
	temperature, _ := client.config.Parameters["temperature"].(float64)
	maxTokens, _ := client.config.Parameters["num_ctx"].(int)
	if maxTokens == 0 {
		maxTokens = 8192
	}
	promptLength := len(prompt)
	previewLength := 500
	preview := prompt
	if len(preview) > previewLength {
		preview = preview[:previewLength] + "..."
	}
	log.Printf("=== AI PROMPT (Full) ===")
	log.Printf("Service: %s, Length: %d chars, Max Tokens: %d", client.service, promptLength, maxTokens)
	log.Printf("Preview (first %d chars):\n%s", previewLength, preview)
	if strings.Contains(prompt, "=== Function Context ===") {
		contextStart := strings.Index(prompt, "=== Function Context ===")
		contextEnd := strings.Index(prompt, "=== End Function Context ===")
		if contextEnd > contextStart {
			contextSection := prompt[contextStart : contextEnd+len("=== End Function Context ===")]
			log.Printf("Function Context Found (%d chars):\n%s", len(contextSection), contextSection)
		}
	} else {
		log.Printf("WARNING: No function context found in prompt!")
	}
	log.Printf("=== Full Prompt (complete) ===")
	log.Printf("%s", prompt)
	log.Printf("=== End Full Prompt ===")
	for retry := 0; retry < MaxRetryAttempts; retry++ {
		var response string
		var err error
		if client.aiIOLogEnabled() {
			client.aiIOLog("PROMPT", prompt, retry)
		}
		switch client.service {
		case "ollama":
			response, err = client.ollamaRequest(prompt, temperature, maxTokens)
		case "openai":
			response, err = client.openAIRequest(prompt, temperature, maxTokens)
		case "deepseek":
			response, err = client.deepSeekRequest(prompt, temperature, maxTokens)
		case "claude":
			response, err = client.claudeRequest(prompt, temperature, maxTokens)
		default:
			return "Invalid AI service configuration"
		}
		if err != nil {
			if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "rate limit") {
				backoff := calculateBackoff(retry)
				time.Sleep(time.Duration(backoff) * time.Second)
				continue
			}
			if retry < MaxRetryAttempts-1 {
				backoff := calculateBackoff(retry)
				time.Sleep(time.Duration(backoff) * time.Second)
				continue
			}
			log.Printf("AI Request Error (retry %d): %v", retry+1, err)
			if client.aiIOLogEnabled() {
				client.aiIOLog("ERROR", fmt.Sprintf("%v", err), retry)
			}
			return fmt.Sprintf("Error: %v", err)
		}
		log.Printf("AI Response received (length: %d chars)", len(response))
		if client.aiIOLogEnabled() {
			client.aiIOLog("RESPONSE", response, retry)
		}
		return response
	}
	return "Maximum retry attempts exceeded"
}

func (client *AIServiceClient) aiIOLogEnabled() bool {
	if client == nil || client.config == nil || client.config.Parameters == nil {
		return false
	}
	v, ok := client.config.Parameters["log_ai_io"]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func (client *AIServiceClient) aiIOLogMaxChars() int {
	if v, ok := client.config.Parameters["ai_log_max_chars"]; ok {
		switch t := v.(type) {
		case int:
			if t > 0 {
				return t
			}
		case float64:
			if int(t) > 0 {
				return int(t)
			}
		}
	}
	return 0 
}

func (client *AIServiceClient) aiIOLogFile() string {
	if v, ok := client.config.Parameters["ai_log_file"].(string); ok && v != "" {
		return v
	}
	return filepath.Join("logs", "ai_payloads.log")
}

func (client *AIServiceClient) aiIOLog(kind string, content string, attempt int) {
	max := client.aiIOLogMaxChars()
	originalLength := len(content)
	truncated := false
	
	if max > 0 && len(content) > max {
		content = content[:max]
		truncated = true
	}
	
	path := client.aiIOLogFile()
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	
	var entry strings.Builder
	entry.WriteString("=" + strings.Repeat("=", 78) + "=\n")
	entry.WriteString(fmt.Sprintf("TIMESTAMP: %s\n", timestamp))
	entry.WriteString(fmt.Sprintf("SERVICE:   %s\n", client.service))
	entry.WriteString(fmt.Sprintf("ATTEMPT:   %d\n", attempt+1))
	entry.WriteString(fmt.Sprintf("TYPE:      %s\n", kind))
	entry.WriteString(fmt.Sprintf("LENGTH:    %d characters", originalLength))
	
	if truncated {
		entry.WriteString(fmt.Sprintf(" (truncated to %d)\n", max))
	} else {
		entry.WriteString("\n")
	}
	
	entry.WriteString("=" + strings.Repeat("=", 78) + "=\n\n")
	entry.WriteString(content)
	entry.WriteString("\n\n")
	
	if truncated {
		entry.WriteString(fmt.Sprintf("\n[... TRUNCATED - Original length: %d characters ...]\n\n", originalLength))
	}
	
	entry.WriteString(strings.Repeat("-", 80) + "\n\n")
	
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Warning: Failed to write to AI log file: %v", err)
		return
	}
	defer f.Close()
	
	if _, err := f.WriteString(entry.String()); err != nil {
		log.Printf("Warning: Failed to write to AI log: %v", err)
	}
}

func (client *AIServiceClient) doHTTPRequest(url string, headers map[string]string, body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	httpClient := &http.Client{}
	if client.timeout > 0 {
		httpClient.Timeout = client.timeout
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func (client *AIServiceClient) ollamaRequest(prompt string, temperature float64, maxTokens int) (string, error) {
	url, _ := client.config.Ollama["url"].(string)
	model, _ := client.config.Ollama["model"].(string)
	requestBody := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": temperature,
			"num_ctx":     maxTokens,
		},
	}
	data, _ := json.Marshal(requestBody)
	headers := map[string]string{"Content-Type": "application/json"}
	respBody, err := client.doHTTPRequest(url+"/api/generate", headers, data)
	if err != nil {
		return "", err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	if response, ok := result["response"].(string); ok {
		return response, nil
	}
	return "No AI response", nil
}

func (client *AIServiceClient) openAIRequest(prompt string, temperature float64, maxTokens int) (string, error) {
	baseURL, _ := client.config.OpenAI["base_url"].(string)
	model, _ := client.config.OpenAI["model"].(string)
	apiKey, _ := client.config.OpenAI["key"].(string)
	requestBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": temperature,
		"max_tokens":  maxTokens,
	}
	data, _ := json.Marshal(requestBody)
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer " + apiKey,
	}
	respBody, err := client.doHTTPRequest(baseURL+"/chat/completions", headers, data)
	if err != nil {
		return "", err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if message, ok := choice["message"].(map[string]interface{}); ok {
				if content, ok := message["content"].(string); ok {
					return content, nil
				}
			}
		}
	}
	return "No AI response", nil
}

func (client *AIServiceClient) deepSeekRequest(prompt string, temperature float64, maxTokens int) (string, error) {
	baseURL, _ := client.config.DeepSeek["base_url"].(string)
	model, _ := client.config.DeepSeek["model"].(string)
	apiKey, _ := client.config.DeepSeek["key"].(string)
	requestBody := map[string]interface{}{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": temperature,
		"max_tokens":  maxTokens,
	}
	data, _ := json.Marshal(requestBody)
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer " + apiKey,
	}
	respBody, err := client.doHTTPRequest(baseURL+"/chat/completions", headers, data)
	if err != nil {
		return "", err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if message, ok := choice["message"].(map[string]interface{}); ok {
				if content, ok := message["content"].(string); ok {
					return content, nil
				}
			}
		}
	}
	return "No AI response", nil
}

func (client *AIServiceClient) claudeRequest(prompt string, temperature float64, maxTokens int) (string, error) {
	baseURL, _ := client.config.Claude["base_url"].(string)
	model, _ := client.config.Claude["model"].(string)
	apiKey, _ := client.config.Claude["key"].(string)
	requestBody := map[string]interface{}{
		"model":       model,
		"max_tokens":  maxTokens,
		"temperature": temperature,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	data, _ := json.Marshal(requestBody)
	headers := map[string]string{
		"Content-Type":      "application/json",
		"x-api-key":         apiKey,
		"anthropic-version": "2023-06-01",
	}
	respBody, err := client.doHTTPRequest(baseURL+"/messages", headers, data)
	if err != nil {
		return "", err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	if content, ok := result["content"].([]interface{}); ok && len(content) > 0 {
		if item, ok := content[0].(map[string]interface{}); ok {
			if text, ok := item["text"].(string); ok {
				return text, nil
			}
		}
	}
	return "No AI response", nil
}

func calculateBackoff(retryCount int) int {
	if retryCount <= 10 {
		backoff := 1
		for i := 0; i < retryCount; i++ {
			backoff *= RateLimitBackoff
		}
		if backoff > MaxBackoffTime {
			return MaxBackoffTime
		}
		return backoff
	}
	backoff := retryCount * RateLimitBackoff
	if backoff > MaxBackoffTime {
		return MaxBackoffTime
	}
	return backoff
}

func GetAIAnalysis(filePath, diffContent string) string {
	if config == nil {
		return "AI configuration not loaded"
	}
	startTime := time.Now()
	prompt := strings.ReplaceAll(config.Prompts["main_analysis"], "{file_path}", filePath)
	prompt = strings.ReplaceAll(prompt, "{diff_content}", diffContent)
	log.Printf("=== GetAIAnalysis called ===")
	log.Printf("File: %s", filePath)
	log.Printf("Diff content length: %d chars", len(diffContent))
	log.Printf("Final prompt length: %d chars", len(prompt))
	if strings.Contains(diffContent, "=== Function Context ===") {
		log.Printf("✓ Function context is included in diffContent")
	} else {
		log.Printf("⚠ Function context NOT found in diffContent - this may be expected if no context was extracted")
	}
	client := NewAIServiceClient(config)
	
	
	if client.aiIOLogEnabled() {
		metadata := fmt.Sprintf("ANALYSIS METADATA\n"+
			"File Path: %s\n"+
			"Timestamp: %s\n"+
			"Prompt Template: main_analysis\n"+
			"Diff Length: %d chars\n"+
			"Function Context: %v\n",
			filePath,
			time.Now().Format("2006-01-02 15:04:05"),
			len(diffContent),
			strings.Contains(diffContent, "=== Function Context ==="))
		client.aiIOLog("METADATA", metadata, 0)
	}
	
	response := client.GenerateResponse(prompt)
	duration := time.Since(startTime)
	log.Printf("GetAIAnalysis completed in %v", duration)
	
	
	if client.aiIOLogEnabled() {
		completionMeta := fmt.Sprintf("ANALYSIS COMPLETION\n"+
			"File Path: %s\n"+
			"Duration: %v\n"+
			"Response Length: %d chars\n",
			filePath,
			duration,
			len(response))
		client.aiIOLog("COMPLETION", completionMeta, 0)
	}
	
	return response
}

func GetCVEDescription(cveID string) string {
	url := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Sprintf("Failed to fetch CVE description: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("Failed to fetch CVE description: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("Failed to fetch CVE description: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("Failed to read CVE description: %v", err)
	}
	bodyStr := string(body)
	startMarker := `data-testid="vuln-description"`
	startIdx := strings.Index(bodyStr, startMarker)
	if startIdx == -1 {
		return "CVE description not found on page"
	}
	openTagStart := strings.Index(bodyStr[startIdx:], ">")
	if openTagStart == -1 {
		return "CVE description format not recognized"
	}
	descStart := startIdx + openTagStart + 1
	closeTagStart := strings.Index(bodyStr[descStart:], "</p>")
	if closeTagStart == -1 {
		return "CVE description closing tag not found"
	}
	description := strings.TrimSpace(bodyStr[descStart : descStart+closeTagStart])
	description = strings.ReplaceAll(description, "&amp;", "&")
	description = strings.ReplaceAll(description, "&lt;", "<")
	description = strings.ReplaceAll(description, "&gt;", ">")
	description = strings.ReplaceAll(description, "&quot;", "\"")
	description = strings.ReplaceAll(description, "&#39;", "'")
	description = strings.ReplaceAll(description, "\n", " ")
	description = strings.ReplaceAll(description, "\t", " ")
	for strings.Contains(description, "  ") {
		description = strings.ReplaceAll(description, "  ", " ")
	}
	if len(description) == 0 {
		return "CVE description is empty"
	}
	return description
}

func AnalyzeWithCVE(aiResponse, cveDescription string) string {
	if config == nil {
		return "AI configuration not loaded"
	}
	prompt := strings.ReplaceAll(config.Prompts["cve_analysis"], "{ai_response}", aiResponse)
	prompt = strings.ReplaceAll(prompt, "{cve_description}", cveDescription)
	
	client := NewAIServiceClient(config)
	
	
	if client.aiIOLogEnabled() {
		metadata := fmt.Sprintf("CVE ANALYSIS METADATA\n"+
			"Timestamp: %s\n"+
			"Prompt Template: cve_analysis\n"+
			"AI Response Length: %d chars\n"+
			"CVE Description Length: %d chars\n",
			time.Now().Format("2006-01-02 15:04:05"),
			len(aiResponse),
			len(cveDescription))
		client.aiIOLog("CVE_METADATA", metadata, 0)
	}
	
	return client.GenerateResponse(prompt)
}

func GenerateCVEWriteup(cveID, cveDescription string, matchingFilesAnalysis []string) string {
	if config == nil {
		return "AI configuration not loaded"
	}
	allAnalysis := strings.Join(matchingFilesAnalysis, "\n\n---\n\n")
	prompt, exists := config.Prompts["cve_writeup"]
	if !exists {
		prompt = DefaultPrompts()["cve_writeup"]
	}
	prompt = strings.ReplaceAll(prompt, "{cve_id}", cveID)
	prompt = strings.ReplaceAll(prompt, "{cve_description}", cveDescription)
	prompt = strings.ReplaceAll(prompt, "{all_matching_files_analysis}", allAnalysis)
	
	log.Printf("Generating writeup for %s", cveID)
	
	client := NewAIServiceClient(config)
	
	
	if client.aiIOLogEnabled() {
		metadata := fmt.Sprintf("CVE WRITEUP METADATA\n"+
			"CVE ID: %s\n"+
			"Timestamp: %s\n"+
			"Prompt Template: cve_writeup\n"+
			"Number of Files: %d\n"+
			"Total Analysis Length: %d chars\n"+
			"CVE Description Length: %d chars\n",
			cveID,
			time.Now().Format("2006-01-02 15:04:05"),
			len(matchingFilesAnalysis),
			len(allAnalysis),
			len(cveDescription))
		client.aiIOLog("CVE_WRITEUP_METADATA", metadata, 0)
	}
	
	writeup := client.GenerateResponse(prompt)
	log.Printf("Generated writeup for %s (%d chars)", cveID, len(writeup))
	
	return writeup
}
