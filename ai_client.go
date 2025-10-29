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
				log.Printf("Rate limited, backing off for %v seconds", backoff)
				time.Sleep(time.Duration(backoff) * time.Second)
				continue
			}

			if retry < MaxRetryAttempts-1 {
				backoff := calculateBackoff(retry)
				time.Sleep(time.Duration(backoff) * time.Second)
				continue
			}

			if client.aiIOLogEnabled() {
				client.aiIOLog("ERROR", fmt.Sprintf("%v", err), retry)
			}
			return fmt.Sprintf("Error: %v", err)
		}

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
    if client == nil || client.config == nil || client.config.Parameters == nil {
        return 100000
    }
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
    return 100000
}

func (client *AIServiceClient) aiIOLogFile() string {
    if client == nil || client.config == nil || client.config.Parameters == nil {
        return filepath.Join("logs", "ai_payloads.log")
    }
    if v, ok := client.config.Parameters["ai_log_file"].(string); ok && v != "" {
        return v
    }
    return filepath.Join("logs", "ai_payloads.log")
}

func (client *AIServiceClient) aiIOLog(kind string, content string, attempt int) {
    
    max := client.aiIOLogMaxChars()
    if len(content) > max {
        content = content[:max] + "\n... [truncated]"
    }
    
    path := client.aiIOLogFile()
    _ = os.MkdirAll(filepath.Dir(path), 0755)

    
    timestamp := time.Now().Format(time.RFC3339)
    header := fmt.Sprintf("[%s] service=%s attempt=%d kind=%s\n", timestamp, client.service, attempt+1, kind)
    entry := header + content + "\n\n"

    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        log.Printf("Failed to open AI I/O log file: %v", err)
        return
    }
    defer f.Close()
    if _, err := f.WriteString(entry); err != nil {
        log.Printf("Failed to write AI I/O log file: %v", err)
    }
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
	req, err := http.NewRequest("POST", url+"/api/generate", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{}
	if client.timeout > 0 {
		httpClient.Timeout = client.timeout
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
	req, err := http.NewRequest("POST", baseURL+"/chat/completions", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	httpClient := &http.Client{}
	if client.timeout > 0 {
		httpClient.Timeout = client.timeout
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
	req, err := http.NewRequest("POST", baseURL+"/chat/completions", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	httpClient := &http.Client{}
	if client.timeout > 0 {
		httpClient.Timeout = client.timeout
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
		"model":      model,
		"max_tokens": maxTokens,
		"temperature": temperature,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	data, _ := json.Marshal(requestBody)
	req, err := http.NewRequest("POST", baseURL+"/messages", bytes.NewBuffer(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	httpClient := &http.Client{}
	if client.timeout > 0 {
		httpClient.Timeout = client.timeout
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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

	prompt := strings.ReplaceAll(config.Prompts["main_analysis"], "{file_path}", filePath)
	prompt = strings.ReplaceAll(prompt, "{diff_content}", diffContent)

	client := NewAIServiceClient(config)
	return client.GenerateResponse(prompt)
}

func GetAICVEAnalysis(filePath, diffContent, cveID, cveDescription string) string {
	if config == nil {
		return "AI configuration not loaded"
	}

	prompt := strings.ReplaceAll(config.Prompts["cve_analysis"], "{ai_response}", "Analyzing code changes for CVE match")
	prompt = strings.ReplaceAll(prompt, "{cve_description}", cveDescription)
	
	fullPrompt := fmt.Sprintf("File: %s\n\nDiff Content:\n%s\n\n%s", filePath, diffContent, prompt)

	client := NewAIServiceClient(config)
	return client.GenerateResponse(fullPrompt)
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
	
	description := strings.TrimSpace(bodyStr[descStart:descStart+closeTagStart])
	
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
	return client.GenerateResponse(prompt)
}

