package main
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)
type RealWorldTest struct {
	ProjectName   string
	Language      string
	Version1      string
	Version2      string
	DownloadURL1  string
	DownloadURL2  string
	ExpectedDiffs int
}
type cacheMetadata struct {
	Project       string    `json:"project"`
	Language      string    `json:"language"`
	Version       string    `json:"version"`
	DownloadURL   string    `json:"download_url"`
	CachedAt      time.Time `json:"cached_at"`
	ArchiveSHA256 string    `json:"archive_sha256"`
	ArchiveSize   int64     `json:"archive_size"`
}
type diffArtifact struct {
	Project     string     `json:"project"`
	Language    string     `json:"language"`
	Version1    string     `json:"version_1"`
	Version2    string     `json:"version_2"`
	DiffCount   int        `json:"diff_count"`
	GeneratedAt time.Time  `json:"generated_at"`
	Highlights  []string   `json:"highlights"`
	Files       []DiffFile `json:"files"`
}
func GetRealWorldTests() []RealWorldTest {
	return []RealWorldTest{
		{
			ProjectName:   "WordPress",
			Language:      "php",
			Version1:      "6.3",
			Version2:      "6.3.1",
			DownloadURL1:  "https://github.com/WordPress/WordPress/archive/refs/tags/6.3.zip",
			DownloadURL2:  "https://github.com/WordPress/WordPress/archive/refs/tags/6.3.1.zip",
			ExpectedDiffs: 130,
		},
		{
			ProjectName:   "Laravel Framework",
			Language:      "php",
			Version1:      "10.26.0",
			Version2:      "10.27.0",
			DownloadURL1:  "https://github.com/laravel/framework/archive/refs/tags/v10.26.0.zip",
			DownloadURL2:  "https://github.com/laravel/framework/archive/refs/tags/v10.27.0.zip",
			ExpectedDiffs: 80,
		},
		{
			ProjectName:   "Symfony",
			Language:      "php",
			Version1:      "6.3.0",
			Version2:      "6.3.1",
			DownloadURL1:  "https://github.com/symfony/symfony/archive/refs/tags/v6.3.0.zip",
			DownloadURL2:  "https://github.com/symfony/symfony/archive/refs/tags/v6.3.1.zip",
			ExpectedDiffs: 60,
		},
		{
			ProjectName:   "React",
			Language:      "javascript",
			Version1:      "18.1.0",
			Version2:      "18.2.0",
			DownloadURL1:  "https://github.com/facebook/react/archive/refs/tags/v18.1.0.zip",
			DownloadURL2:  "https://github.com/facebook/react/archive/refs/tags/v18.2.0.zip",
			ExpectedDiffs: 160,
		},
		{
			ProjectName:   "Vue Core",
			Language:      "javascript",
			Version1:      "3.3.7",
			Version2:      "3.3.8",
			DownloadURL1:  "https://github.com/vuejs/core/archive/refs/tags/v3.3.7.zip",
			DownloadURL2:  "https://github.com/vuejs/core/archive/refs/tags/v3.3.8.zip",
			ExpectedDiffs: 70,
		},
		{
			ProjectName:   "Express",
			Language:      "javascript",
			Version1:      "4.18.2",
			Version2:      "4.18.3",
			DownloadURL1:  "https://github.com/expressjs/express/archive/refs/tags/4.18.2.zip",
			DownloadURL2:  "https://github.com/expressjs/express/archive/refs/tags/4.18.3.zip",
			ExpectedDiffs: 18,
		},
		{
			ProjectName:   "NestJS",
			Language:      "typescript",
			Version1:      "10.2.5",
			Version2:      "10.2.6",
			DownloadURL1:  "https://github.com/nestjs/nest/archive/refs/tags/v10.2.5.zip",
			DownloadURL2:  "https://github.com/nestjs/nest/archive/refs/tags/v10.2.6.zip",
			ExpectedDiffs: 35,
		},
		{
			ProjectName:   "TypeScript Compiler",
			Language:      "typescript",
			Version1:      "5.2.2",
			Version2:      "5.3.3",
			DownloadURL1:  "https://github.com/microsoft/TypeScript/archive/refs/tags/v5.2.2.zip",
			DownloadURL2:  "https://github.com/microsoft/TypeScript/archive/refs/tags/v5.3.3.zip",
			ExpectedDiffs: 210,
		},
		{
			ProjectName:   "Django",
			Language:      "python",
			Version1:      "4.2.3",
			Version2:      "4.2.4",
			DownloadURL1:  "https://github.com/django/django/archive/refs/tags/4.2.3.zip",
			DownloadURL2:  "https://github.com/django/django/archive/refs/tags/4.2.4.zip",
			ExpectedDiffs: 90,
		},
		{
			ProjectName:   "Flask",
			Language:      "python",
			Version1:      "2.3.2",
			Version2:      "2.3.3",
			DownloadURL1:  "https://github.com/pallets/flask/archive/refs/tags/2.3.2.zip",
			DownloadURL2:  "https://github.com/pallets/flask/archive/refs/tags/2.3.3.zip",
			ExpectedDiffs: 22,
		},
		{
			ProjectName:   "FastAPI",
			Language:      "python",
			Version1:      "0.99.1",
			Version2:      "0.100.0",
			DownloadURL1:  "https://github.com/tiangolo/fastapi/archive/refs/tags/0.99.1.zip",
			DownloadURL2:  "https://github.com/tiangolo/fastapi/archive/refs/tags/0.100.0.zip",
			ExpectedDiffs: 45,
		},
		{
			ProjectName:   "Gin",
			Language:      "go",
			Version1:      "1.9.0",
			Version2:      "1.9.1",
			DownloadURL1:  "https://github.com/gin-gonic/gin/archive/refs/tags/v1.9.0.zip",
			DownloadURL2:  "https://github.com/gin-gonic/gin/archive/refs/tags/v1.9.1.zip",
			ExpectedDiffs: 28,
		},
		{
			ProjectName:   "Cobra",
			Language:      "go",
			Version1:      "1.7.0",
			Version2:      "1.8.0",
			DownloadURL1:  "https://github.com/spf13/cobra/archive/refs/tags/v1.7.0.zip",
			DownloadURL2:  "https://github.com/spf13/cobra/archive/refs/tags/v1.8.0.zip",
			ExpectedDiffs: 32,
		},
		{
			ProjectName:   "Guava",
			Language:      "java",
			Version1:      "32.1.1",
			Version2:      "32.1.2",
			DownloadURL1:  "https://github.com/google/guava/archive/refs/tags/v32.1.1.zip",
			DownloadURL2:  "https://github.com/google/guava/archive/refs/tags/v32.1.2.zip",
			ExpectedDiffs: 55,
		},
		{
			ProjectName:   "Jackson Databind",
			Language:      "java",
			Version1:      "2.15.1",
			Version2:      "2.15.2",
			DownloadURL1:  "https://github.com/FasterXML/jackson-databind/archive/refs/tags/jackson-databind-2.15.1.zip",
			DownloadURL2:  "https://github.com/FasterXML/jackson-databind/archive/refs/tags/jackson-databind-2.15.2.zip",
			ExpectedDiffs: 48,
		},
		{
			ProjectName:   "Serilog",
			Language:      "csharp",
			Version1:      "3.0.1",
			Version2:      "3.1.0",
			DownloadURL1:  "https://github.com/serilog/serilog/archive/refs/tags/v3.0.1.zip",
			DownloadURL2:  "https://github.com/serilog/serilog/archive/refs/tags/v3.1.0.zip",
			ExpectedDiffs: 26,
		},
		{
			ProjectName:   "NLog",
			Language:      "csharp",
			Version1:      "5.2.0",
			Version2:      "5.2.1",
			DownloadURL1:  "https://github.com/NLog/NLog/archive/refs/tags/v5.2.0.zip",
			DownloadURL2:  "https://github.com/NLog/NLog/archive/refs/tags/v5.2.1.zip",
			ExpectedDiffs: 20,
		},
		{
			ProjectName:   "libgit2",
			Language:      "c",
			Version1:      "1.7.1",
			Version2:      "1.7.2",
			DownloadURL1:  "https://github.com/libgit2/libgit2/archive/refs/tags/v1.7.1.zip",
			DownloadURL2:  "https://github.com/libgit2/libgit2/archive/refs/tags/v1.7.2.zip",
			ExpectedDiffs: 68,
		},
		{
			ProjectName:   "libpng",
			Language:      "c",
			Version1:      "1.6.39",
			Version2:      "1.6.40",
			DownloadURL1:  "https://github.com/glennrp/libpng/archive/refs/tags/v1.6.39.zip",
			DownloadURL2:  "https://github.com/glennrp/libpng/archive/refs/tags/v1.6.40.zip",
			ExpectedDiffs: 35,
		},
		{
			ProjectName:   "fmt",
			Language:      "cpp",
			Version1:      "10.1.0",
			Version2:      "10.1.1",
			DownloadURL1:  "https://github.com/fmtlib/fmt/archive/refs/tags/10.1.0.zip",
			DownloadURL2:  "https://github.com/fmtlib/fmt/archive/refs/tags/10.1.1.zip",
			ExpectedDiffs: 36,
		},
		{
			ProjectName:   "Google Benchmark",
			Language:      "cpp",
			Version1:      "1.7.1",
			Version2:      "1.8.0",
			DownloadURL1:  "https://github.com/google/benchmark/archive/refs/tags/v1.7.1.zip",
			DownloadURL2:  "https://github.com/google/benchmark/archive/refs/tags/v1.8.0.zip",
			ExpectedDiffs: 38,
		},
		{
			ProjectName:   "Ruby on Rails",
			Language:      "ruby",
			Version1:      "7.1.2",
			Version2:      "7.1.3",
			DownloadURL1:  "https://github.com/rails/rails/archive/refs/tags/v7.1.2.zip",
			DownloadURL2:  "https://github.com/rails/rails/archive/refs/tags/v7.1.3.zip",
			ExpectedDiffs: 85,
		},
		{
			ProjectName:   "Jekyll",
			Language:      "ruby",
			Version1:      "4.3.1",
			Version2:      "4.3.2",
			DownloadURL1:  "https://github.com/jekyll/jekyll/archive/refs/tags/v4.3.1.zip",
			DownloadURL2:  "https://github.com/jekyll/jekyll/archive/refs/tags/v4.3.2.zip",
			ExpectedDiffs: 28,
		},
		{
			ProjectName:   "ripgrep",
			Language:      "rust",
			Version1:      "14.0.0",
			Version2:      "14.1.0",
			DownloadURL1:  "https://github.com/BurntSushi/ripgrep/archive/refs/tags/14.0.0.zip",
			DownloadURL2:  "https://github.com/BurntSushi/ripgrep/archive/refs/tags/14.1.0.zip",
			ExpectedDiffs: 44,
		},
		{
			ProjectName:   "Tokio",
			Language:      "rust",
			Version1:      "1.35.0",
			Version2:      "1.36.0",
			DownloadURL1:  "https://github.com/tokio-rs/tokio/archive/refs/tags/tokio-1.35.0.zip",
			DownloadURL2:  "https://github.com/tokio-rs/tokio/archive/refs/tags/tokio-1.36.0.zip",
			ExpectedDiffs: 62,
		},
	}
}
func DownloadProject(test *RealWorldTest, version string, url string) (string, error) {
	cacheDir := "cache"
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache directory: %w", err)
	}
	baseKey := fmt.Sprintf("%s_%s", sanitizeForPath(test.ProjectName), strings.ToLower(test.Language))
	cacheKey := fmt.Sprintf("%s_%s", baseKey, sanitizeForPath(version))
	cachePath := filepath.Join(cacheDir, cacheKey)
	markerPath := filepath.Join(cachePath, ".ready")
	metadataPath := filepath.Join(cachePath, ".metadata.json")
	if info, err := os.Stat(cachePath); err == nil && info.IsDir() {
		if _, err := os.Stat(markerPath); err == nil {
			return cachePath, nil
		}
		if err := os.RemoveAll(cachePath); err != nil {
			return "", fmt.Errorf("failed to clear incomplete cache: %w", err)
		}
	}
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(attempt-1) * time.Second
			time.Sleep(backoff)
		} else {
		}
		if err := fetchAndCacheProject(test, version, url, cachePath, markerPath, metadataPath); err != nil {
			lastErr = err
			continue
		}
		return cachePath, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unknown error")
	}
	return "", fmt.Errorf("failed to download %s %s after %d attempts: %w", test.ProjectName, version, maxAttempts, lastErr)
}
func fetchAndCacheProject(test *RealWorldTest, version, url, cachePath, markerPath, metadataPath string) error {
	tempDir, err := os.MkdirTemp("", fmt.Sprintf("test_%s_%s_*", sanitizeForPath(test.ProjectName), sanitizeForPath(version)))
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download: status %d", resp.StatusCode)
	}
	zipPath := filepath.Join(tempDir, "version.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create archive file: %w", err)
	}
	hasher := sha256.New()
	written, err := TrackedCopy(io.MultiWriter(zipFile, hasher), resp.Body)
	if closeErr := zipFile.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("failed to save archive: %w", err)
	}
	if written < 1024 {
		return fmt.Errorf("downloaded archive too small (%d bytes)", written)
	}
	if resp.ContentLength > 0 && written != resp.ContentLength {
		return fmt.Errorf("downloaded archive size mismatch: expected %d, got %d", resp.ContentLength, written)
	}
	archiveSHA := hex.EncodeToString(hasher.Sum(nil))
	extractPath := filepath.Join(tempDir, "extracted")
	if err := extractZip(zipPath, extractPath); err != nil {
		return fmt.Errorf("failed to extract archive: %w", err)
	}
	entries, err := os.ReadDir(extractPath)
	if err != nil {
		return fmt.Errorf("failed to inspect extracted archive: %w", err)
	}
	var sourcePath string
	for _, entry := range entries {
		if entry.IsDir() {
			sourcePath = filepath.Join(extractPath, entry.Name())
			break
		}
	}
	if sourcePath == "" {
		return fmt.Errorf("no directory found in extracted archive")
	}
	if err := os.RemoveAll(cachePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clear cache path: %w", err)
	}
	if err := copyDirectory(sourcePath, cachePath); err != nil {
		return fmt.Errorf("failed to cache: %w", err)
	}
	metadata := cacheMetadata{
		Project:       test.ProjectName,
		Language:      test.Language,
		Version:       version,
		DownloadURL:   url,
		CachedAt:      time.Now().UTC(),
		ArchiveSHA256: archiveSHA,
		ArchiveSize:   written,
	}
	if err := writeJSONFile(metadataPath, metadata); err != nil {
		return fmt.Errorf("failed to write cache metadata: %w", err)
	}
	if err := TrackedWriteFile(markerPath, []byte(archiveSHA), 0644); err != nil {
		return fmt.Errorf("failed to write cache marker: %w", err)
	}
	return nil
}
func RunPatchDiff(test *RealWorldTest) (*AnalysisResult, error) {
	oldPath, err := DownloadProject(test, test.Version1, test.DownloadURL1)
	if err != nil {
		return nil, fmt.Errorf("failed to download version 1: %v", err)
	}
	newPath, err := DownloadProject(test, test.Version2, test.DownloadURL2)
	if err != nil {
		return nil, fmt.Errorf("failed to download version 2: %v", err)
	}
	var extension string
	switch test.Language {
	case "php":
		extension = ".php"
	case "javascript":
		extension = ".js,.jsx,.mjs"
	case "python":
		extension = ".py"
	case "go":
		extension = ".go"
	case "java":
		extension = ".java"
	case "csharp":
		extension = ".cs"
	case "typescript":
		extension = ".ts,.tsx"
	case "c":
		extension = ".c,.h"
	case "cpp":
		extension = ".cpp,.cc,.cxx,.hpp,.hxx,.h++"
	case "ruby":
		extension = ".rb"
	case "rust":
		extension = ".rs"
	default:
		extension = ""
	}
	diffs := compareDirectories(oldPath, newPath, extension)
	if _, err := saveDiffArtifacts(test, diffs); err != nil {
	} else {
	}
	results := analyzeDiffsForVulnerabilities(diffs, "", "")
	if config != nil && len(results) > 0 {
		results = runAIAnalysisOnResults(results, "", *aiThreads, newPath)
	}
	summary := &AnalysisResult{
		Context: []string{
			fmt.Sprintf("Test: %s", test.ProjectName),
			fmt.Sprintf("Language: %s", test.Language),
			fmt.Sprintf("Versions: %s -> %s", test.Version1, test.Version2),
			fmt.Sprintf("Files analyzed: %d", len(diffs)),
			fmt.Sprintf("Results: %d", len(results)),
		},
	}
	return summary, nil
}
func ValidateResults(test *RealWorldTest, result *AnalysisResult) []string {
	var issues []string
	if len(result.Context) < 3 {
		issues = append(issues, "Result context seems incomplete")
	}
	contextStr := strings.Join(result.Context, "\n")
	if strings.Contains(contextStr, "function not found") && !strings.Contains(contextStr, "external library") {
		issues = append(issues, "Found 'function not found' errors that may indicate missing function definitions")
	}
	return issues
}
func saveDiffArtifacts(test *RealWorldTest, diffs []DiffFile) (string, error) {
	baseDir := filepath.Join("cache", fmt.Sprintf("%s_%s", sanitizeForPath(test.ProjectName), strings.ToLower(test.Language)), "diffs")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return "", err
	}
	fileName := fmt.Sprintf("%s_to_%s.json", sanitizeForPath(test.Version1), sanitizeForPath(test.Version2))
	artifactPath := filepath.Join(baseDir, fileName)
	highlightCount := len(diffs)
	if highlightCount > 5 {
		highlightCount = 5
	}
	highlights := make([]string, 0, highlightCount)
	for i := 0; i < highlightCount; i++ {
		highlights = append(highlights, fmt.Sprintf("%s (%s)", diffs[i].Filename, diffs[i].Type))
	}
	artifact := diffArtifact{
		Project:     test.ProjectName,
		Language:    test.Language,
		Version1:    test.Version1,
		Version2:    test.Version2,
		DiffCount:   len(diffs),
		GeneratedAt: time.Now().UTC(),
		Highlights:  highlights,
		Files:       diffs,
	}
	if err := writeJSONFile(artifactPath, artifact); err != nil {
		return "", err
	}
	return artifactPath, nil
}
func sanitizeForPath(value string) string {
	if value == "" {
		return "unknown"
	}
	value = strings.ToLower(value)
	var builder strings.Builder
	builder.Grow(len(value))
	underscore := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			underscore = false
			continue
		}
		if !underscore {
			builder.WriteRune('_')
			underscore = true
		}
	}
	sanitized := strings.Trim(builder.String(), "_")
	if sanitized == "" {
		return "value"
	}
	return sanitized
}
func writeJSONFile(path string, payload interface{}) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return TrackedWriteFile(path, data, 0644)
}
func RunRealWorldTests(languages []string) error {
	tests := GetRealWorldTests()
	if len(languages) > 0 {
		filtered := []RealWorldTest{}
		for _, test := range tests {
			for _, lang := range languages {
				if test.Language == lang {
					filtered = append(filtered, test)
					break
				}
			}
		}
		tests = filtered
	}
	if len(tests) == 0 {
		return fmt.Errorf("no tests found for specified languages")
	}
	successCount := 0
	failureCount := 0
	for _, test := range tests {
		startTime := time.Now()
		result, err := RunPatchDiff(&test)
		_ = time.Since(startTime)
		if err != nil {
			failureCount++
			continue
		}
		issues := ValidateResults(&test, result)
		if len(issues) > 0 {
			for _, _ = range issues {
			}
		}
		successCount++
	}
	if failureCount > 0 {
		return fmt.Errorf("%d tests failed", failureCount)
	}
	return nil
}
