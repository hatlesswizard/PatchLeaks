package main

import (
	"encoding/json"
	"os"
)

const (
	AIConfigFile = "ai_config.json"
)

// Config represents the AI configuration
type Config struct {
	Service    string                 `json:"service"`
	Ollama     map[string]interface{} `json:"ollama"`
	OpenAI     map[string]interface{} `json:"openai"`
	DeepSeek   map[string]interface{} `json:"deepseek"`
	Claude     map[string]interface{} `json:"claude"`
	Parameters map[string]interface{} `json:"parameters"`
	Prompts    map[string]string      `json:"prompts"`
}

// LoadConfig loads the AI configuration from file
func LoadConfig() (*Config, error) {
	data, err := os.ReadFile(AIConfigFile)
	if err != nil {
		return DefaultConfig(), nil
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Ensure all fields are populated
	defaultConfig := DefaultConfig()
	if config.Ollama == nil {
		config.Ollama = defaultConfig.Ollama
	}
	if config.OpenAI == nil {
		config.OpenAI = defaultConfig.OpenAI
	}
	if config.DeepSeek == nil {
		config.DeepSeek = defaultConfig.DeepSeek
	}
	if config.Claude == nil {
		config.Claude = defaultConfig.Claude
	}
	if config.Prompts == nil || len(config.Prompts) == 0 {
		config.Prompts = defaultConfig.Prompts
	}

	return &config, nil
}

// Save saves the configuration to file
func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(AIConfigFile, data, 0644)
}

// GetServiceConfig returns the configuration for a specific service
func (c *Config) GetServiceConfig(service string) (map[string]interface{}, bool) {
	switch service {
	case "ollama":
		return c.Ollama, c.Ollama != nil
	case "openai":
		return c.OpenAI, c.OpenAI != nil
	case "deepseek":
		return c.DeepSeek, c.DeepSeek != nil
	case "claude":
		return c.Claude, c.Claude != nil
	default:
		return nil, false
	}
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Service: "ollama",
		Ollama: map[string]interface{}{
			"url":   "http://localhost:11434",
			"model": "qwen2.5-coder:3b",
		},
		OpenAI: map[string]interface{}{
			"key":      "",
			"model":    "gpt-4-turbo",
			"base_url": "https://api.openai.com/v1",
		},
		DeepSeek: map[string]interface{}{
			"key":      "",
			"model":    "deepseek-chat",
			"base_url": "https://api.deepseek.com/v1",
		},
		Claude: map[string]interface{}{
			"key":      "",
			"model":    "claude-3-opus-20240229",
			"base_url": "https://api.anthropic.com/v1",
		},
		Parameters: map[string]interface{}{
			"temperature": 1.0,
			"num_ctx":     8192,
		},
		Prompts: DefaultPrompts(),
	}
}

// DefaultPrompts returns the default prompts
func DefaultPrompts() map[string]string {
	return map[string]string{
		"main_analysis": `Analyze the provided code diff for security fixes.

Instructions:
1. Your answer MUST strictly follow the answer format outlined below.
2. Always include the vulnerability name if one exists.
3. There may be multiple vulnerabilities. For each, provide a separate entry following the structure.
4. Even if you are uncertain whether a vulnerability exists, follow the structure and indicate your uncertainty.

Answer Format for Each Vulnerability:
    Vulnerability Existed: [yes/no/not sure]
    [Vulnerability Name] [File] [Lines]
    [Old Code]
    [Fixed Code]

Additional Details:
    File: {file_path}
    Diff Content:
    {diff_content}`,
		"cve_analysis": `Analysis:
{ai_response}

Question: Do any of the vulnerabilities identified in the analysis match the description?
Reply strictly in this format: 'Description Matches: Yes/No' 

Description:
{cve_description}`,
	}
}

