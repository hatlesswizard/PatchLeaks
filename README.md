# PatchLeaks – From Patch to PoC  
🚀 **[Try PatchLeaks Live Demo](https://pwn.az)** 🚀

[Start with GitHub Repository Analysis](#-github-repository-analysis)

[![GNU AGPL v3 License](https://img.shields.io/badge/License-GNU%20AGPL%20v3-blue)](LICENSE)
[![Issues](https://img.shields.io/github/issues/hatlesswizard/patchleaks)](https://github.com/hatlesswizard/patchleaks/issues)
[![Stars](https://img.shields.io/github/stars/hatlesswizard/patchleaks?style=social)](https://github.com/hatlesswizard/patchleaks/stargazers)

> **Go from a CVE number to the exact patched code and its vulnerability analysis**

---

## Overview
PatchLeaks compares two versions of a code‑base, highlights lines changed by vendor, and explains *why* they matter. Feed the tool an old and a patched version; PatchLeaks spots the security fix and provides detailed description so you can validate—or weaponize—it fast.

---

## Why PatchLeaks?
| **Real-World Challenge** | **Old-School Pain** | **PatchLeaks Fix** |
| :-- | :-- | :-- |
| Hundreds of files change every release | Manual grepping / fragile regex rules | Context‑aware diff analysis that ranks security‑relevant changes first |
| Patches include both old and new code | Most SASTs refuse to scan incomplete code | Tolerates mixed old/new hunks and still reasons about vulnerable flows |
| Logic bugs (ACL, privilege escalation…) | Almost always missed | Language‑model reasoning surfaces non‑trivial logic flaws |
| 0-day triage under the gun | Hours•days of eyeballing | **Minutes** to first actionable insight |

---

## 🚀 Key Features

### 🔍 **Multi-Mode Analysis**
- **🗂️ Folder Analysis** — Compare any two local directories with intelligent diff processing
- **📦 Product Analysis** — Direct GitHub repository integration; PatchLeaks fetches, compares, and reports automatically
- **🎯 CVE Analysis Enhancement** — Optional feature that compares discovered vulnerabilities against specific CVE descriptions
- **🔧 Keyword Scoping** — Focus analysis on specific file extensions and patterns

### 📚 **Automated Library Management**
- **🔄 Continuous Monitoring** — Automatically tracks GitHub repositories for new releases and security updates
- **⚡ Auto-Analysis** — Triggers security analysis automatically when new versions are detected
- **🎛️ Flexible Controls** — Pause/resume monitoring per repository, configure AI service per project
- **📊 Version Tracking** — Maintains history of checked versions and analysis results
- **🔔 Smart Notifications** — Get notified when vulnerabilities are discovered in tracked repositories
- **🏗️ Background Processing** — Runs scheduled checks without interrupting your workflow

### 🤖 **AI-Powered Intelligence**
- **Multiple AI Backends** — Choose from OpenAI GPT-4, Claude, DeepSeek, or local Ollama models
- **Smart Vulnerability Detection** — AI identifies security-relevant changes and explains the impact
- **Logic Flaw Analysis** — Catches subtle bugs like privilege escalation and access control bypasses
- **Contextual Reasoning** — Understands code relationships and data flows

### 📊 **Professional Reporting**
- **Interactive Dashboard** — Beautiful web interface with real-time analysis results
- **Side-by-Side Diffs** — Clean, syntax-highlighted comparisons with inline AI explanations
- **Search & Filter** — Find specific vulnerabilities across all your saved analyses
- **Shareable Reports** — Generate unique links to share findings with your team
- **Export Options** — Save analyses in multiple formats for documentation

---

## 🎯 Perfect For

<table>
<tr>
<td width="50%">

### 🛡️ **Security Researchers**
- **0-day Discovery** — Spot new vulnerabilities in patch releases
- **Exploit Development** — Understand exactly what was fixed and how
- **Vulnerability Analysis** — Get detailed explanations of security implications
- **Research Workflow** — Systematic approach to patch analysis
- **Continuous Monitoring** — Track multiple projects automatically for new security patches

</td>
<td width="50%">

### 🏢 **Enterprise Teams**
- **Patch Assessment** — Understand security fixes before deployment
- **Risk Evaluation** — Prioritize patches based on vulnerability severity
- **Compliance Reporting** — Generate detailed security assessment reports
- **Team Collaboration** — Share findings across security and development teams
- **Automated Monitoring** — Track vendor releases and security updates automatically

</td>
</tr>
</table>

---

## 📋 Prerequisites

Before installing PatchLeaks, ensure you have the following:

### Required
- **Go 1.21+** - [Download Go](https://golang.org/dl/)
- **GCC or Clang** - Required for CGO (tree-sitter compilation)
  - Linux: `sudo apt-get install build-essential`
  - macOS: Install Xcode Command Line Tools: `xcode-select --install`
  - Windows: Install [MinGW-w64](https://www.mingw-w64.org/)
- **Git** - For cloning the repository

### Optional (For Enhanced Builtin Detection)
These language runtimes enable CLI-based extraction of builtin functions. PatchLeaks works without them using comprehensive fallback lists.

- **PHP** - For PHP builtin detection enhancement
- **Python 3** - For Python builtin detection enhancement
- **Ruby** - For Ruby builtin detection enhancement
- **Java JDK** - For Java reflection-based detection (future enhancement)
- **.NET SDK** - For C# reflection-based detection (future enhancement)

---

## 🚀 Quick Start

### 🔧 **Installation**
```bash
# Clone the repository
git clone https://github.com/hatlesswizard/patchleaks.git
cd patchleaks

# Download Go dependencies (includes tree-sitter parsers)
go mod download

# Build the application (CGO is required for tree-sitter)
CGO_ENABLED=1 go build -o patchleaks

# Or simply use 'go build' (CGO is enabled by default)
go build -o patchleaks

# Run the application
./patchleaks -p 8080

# Or run with specific options
./patchleaks -p 8080 -t 4  # 4 AI analysis threads
```

### 🎯 **First Run**
On first run, PatchLeaks will:
1. Create necessary directories (`products/`, `saved_analyses/`, `logs/`)
2. Generate `ai_config.json` if it doesn't exist
3. Initialize the builtin function detector for all supported languages
4. Start the web server with random credentials (displayed in the banner)

---

## 📖 Usage Examples

### 🎯 **CVE Analysis Enhancement**
```bash
# CVE analysis can be added to any analysis mode
1. Start any analysis (Folder, Product, or Library)
2. In the "CVE IDs" field, enter one or more CVE IDs (e.g., CVE-2024-1234)
3. Enable AI analysis
4. Run the analysis as normal
5. AI will compare found vulnerabilities against CVE descriptions
6. Results show "Yes/No" matches for each CVE ID provided
```

### 📁 **Directory Comparison**
```bash
1. Choose "Folder Analysis"
2. Select old version directory
3. Select new version directory
4. Enable AI analysis
5. Configure file filters (optional)
6. Start analysis and review results
```

### 🐙 **GitHub Repository Analysis**
```bash
1. Go to "Product Analysis"
2. Add GitHub repo using "Manage Products"
3. Go back to products and choose name of GitHub repository
4. Select version tags/branches to compare
5. Enable AI analysis
6. Let PatchLeaks fetch and analyze automatically
```

### 📚 **Library Management & Auto-Monitoring**
```bash
# Add Repository to Library
1. Navigate to "Library" section
2. Click "Add Repository"
3. Enter repository name and GitHub URL
4. Select AI service (OpenAI, Claude, DeepSeek, or Ollama)
5. Enable auto-scan for continuous monitoring

# Monitor Repository Activity
- PatchLeaks automatically checks for new releases
- When new versions are detected, analysis runs automatically
- Background scheduler runs periodic checks
- View analysis history and results in dashboard
- Pause/resume monitoring per repository as needed

# Manual Version Check
- Click "Check Now" to manually trigger version checks
- Useful for immediate updates without waiting for scheduled runs
```

---

## 🌐 Supported Languages

PatchLeaks supports comprehensive analysis across 11 programming languages with intelligent builtin detection:

| Language | File Extensions | Builtin Detection | Tree-Sitter Support |
|----------|-----------------|-------------------|---------------------|
| **C** | `.c`, `.h` | Standard library functions (stdio.h, stdlib.h, string.h, math.h, etc.) | ✅ Full |
| **C++** | `.cpp`, `.hpp`, `.cc`, `.cxx`, `.h++`, `.hh`, `.c++`, `.ii`, `.ixx` | STL functions, containers, algorithms, smart pointers | ✅ Full |
| **C#** | `.cs`, `.csx` | .NET Framework/Core methods, LINQ, System.* | ✅ Full |
| **Go** | `.go` | Go builtin functions, types (len, make, append, etc.) | ✅ Full |
| **Java** | `.java` | java.lang.* methods, Collections, Arrays utilities | ✅ Full |
| **JavaScript** | `.js`, `.jsx`, `.mjs`, `.cjs` | Built-in objects, Web APIs, Node.js globals | ✅ Full |
| **PHP** | `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.phps` | PHP core functions, language constructs, extensions | ✅ Full |
| **Python** | `.py`, `.pyi`, `.pyw`, `.pyx` | Python builtins, including dunder methods | ✅ Full |
| **Ruby** | `.rb`, `.rake`, `.gemspec`, `.ru` | Kernel, Object, Enumerable, Array, Hash methods | ✅ Full |
| **Rust** | `.rs`, `.rlib` | Prelude items, macros (println!, vec!, etc.), std traits | ✅ Full |
| **TypeScript** | `.ts`, `.tsx`, `.mts`, `.cts` | TypeScript + JavaScript builtins | ✅ Full |

### Builtin Detection Features

- **CLI-Based Extraction**: Dynamically extracts builtins from installed language runtimes (PHP, Python, Ruby, Go)
- **Comprehensive Fallbacks**: Works without runtime installations using curated builtin lists
- **Language Constructs**: Recognizes language-specific constructs (PHP's `array`, `isset`, etc.)
- **Macro Support**: Handles Rust macros with and without `!` suffix
- **Special Methods**: Includes Ruby's `?` methods, Python's `__dunder__` methods

---

## 🖥️ Command-Line Options

```
Usage: ./patchleaks [options]

Options:
  -p <port>          Port to run the server on (default: random free port)
  -host <address>    Host address to bind to (default: 127.0.0.1)
  -t <threads>       Number of AI analysis threads (default: 1)
  -test-real-world   Run real-world validation tests instead of starting server
  -language <langs>  Comma-separated list of languages for testing (e.g., php,python,javascript)

Examples:
  ./patchleaks                           # Start with random port
  ./patchleaks -p 8080                   # Start on port 8080
  ./patchleaks -p 8080 -t 4              # Use 4 AI threads
  ./patchleaks -host 0.0.0.0 -p 8080     # Bind to all interfaces
  ./patchleaks -test-real-world          # Run validation tests
  ./patchleaks -test-real-world -language php,python  # Test specific languages
```

---

## 🧪 Testing

### Unit Tests
```bash
# Run all unit tests
go test ./... -v

# Run specific test suites
go test -run TestBuiltinDetector -v     # Test builtin detection
go test -run TestDetectLanguage -v       # Test file extension detection
```

### Real-World Validation
```bash
# Run comprehensive real-world tests on actual open-source projects
./patchleaks -test-real-world

# Test specific languages only
./patchleaks -test-real-world -language php,javascript,python

# View detailed test logs
tail -f real_world_run.log
```

Real-world tests analyze actual version comparisons of popular projects:
- **PHP**: WordPress, Laravel, Symfony
- **JavaScript**: React, Vue, Express
- **Python**: Django, Flask, FastAPI
- **Go**: Gin, Cobra
- **Rust**: Tokio, Ripgrep
- **C/C++**: libgit2, libpng, curl, fmt, Google Benchmark
- **Java**: Guava, Jackson
- **Ruby**: Jekyll, Rails
- **C#**: NLog, Serilog
- **TypeScript**: NestJS, TypeScript Compiler

---

## 🔧 Configuration

### 🤖 **AI Provider Setup**

PatchLeaks uses `ai_config.json` for AI service configuration. The file is created automatically on first run with default settings.

#### Configuration Structure

```json
{
  "service": "deepseek",  // Active service: openai, claude, deepseek, or ollama
  
  "openai": {
    "key": "",
    "model": "gpt-4-turbo",
    "base_url": "https://api.openai.com/v1"
  },
  
  "claude": {
    "key": "",
    "model": "claude-3-5-sonnet-20241022",
    "base_url": "https://api.anthropic.com/v1"
  },
  
  "deepseek": {
    "key": "",
    "model": "deepseek-chat",
    "base_url": "https://api.deepseek.com/v1"
  },
  
  "ollama": {
    "url": "http://localhost:11434",
    "model": "qwen2.5-coder:7b"
  },
  
  "parameters": {
    "temperature": 1.0,           // Response randomness (0.0-2.0)
    "num_ctx": 8192,              // Context window size
    "log_ai_io": true,            // Log AI requests/responses
    "ai_log_max_chars": 100000,   // Max characters per log entry
    "ai_log_file": "logs/ai_payloads.log"
  },
  
  "prompts": {
    "main_analysis": "...",       // Main vulnerability analysis prompt
    "cve_analysis": "..."         // CVE matching prompt
  }
}
```

#### Quick Setup Examples

<details>
<summary><strong>🔸 OpenAI GPT-4</strong></summary>

1. Get API key from [OpenAI Platform](https://platform.openai.com/api-keys)
2. Edit `ai_config.json`:
```json
{
  "service": "openai",
  "openai": {
    "key": "sk-your-api-key-here",
    "model": "gpt-4-turbo",
    "base_url": "https://api.openai.com/v1"
  }
}
```
</details>

<details>
<summary><strong>🔸 Anthropic Claude</strong></summary>

1. Get API key from [Anthropic Console](https://console.anthropic.com/)
2. Edit `ai_config.json`:
```json
{
  "service": "claude",
  "claude": {
    "key": "sk-ant-your-api-key-here",
    "model": "claude-3-5-sonnet-20241022",
    "base_url": "https://api.anthropic.com/v1"
  }
}
```
</details>

<details>
<summary><strong>🔸 DeepSeek (Budget-Friendly)</strong></summary>

1. Get API key from [DeepSeek Platform](https://platform.deepseek.com/)
2. Edit `ai_config.json`:
```json
{
  "service": "deepseek",
  "deepseek": {
    "key": "sk-your-deepseek-key",
    "model": "deepseek-chat",
    "base_url": "https://api.deepseek.com/v1"
  }
}
```
</details>

<details>
<summary><strong>🔸 Local Ollama (Privacy-First)</strong></summary>

1. Install [Ollama](https://ollama.ai/)
2. Pull a model: `ollama pull qwen2.5-coder:7b`
3. Edit `ai_config.json`:
```json
{
  "service": "ollama",
  "ollama": {
    "url": "http://localhost:11434",
    "model": "qwen2.5-coder:7b"
  }
}
```
</details>

#### Custom Prompts

You can customize analysis prompts in `ai_config.json` or via the web UI at `/ai-settings`. The prompts support placeholders like `{file_path}`, `{diff_content}`, and `{cve_description}`.

---

## 🔧 Troubleshooting

### CGO Compilation Errors

**Problem**: `fatal error: 'tree_sitter/api.h' file not found`

**Solution**:
```bash
# Ensure CGO is enabled
export CGO_ENABLED=1

# Install build tools
# Linux:
sudo apt-get install build-essential

# macOS:
xcode-select --install

# Windows:
# Install MinGW-w64 and add to PATH
```

### Tree-Sitter Build Issues

**Problem**: Build fails with tree-sitter related errors

**Solution**:
```bash
# Clean Go cache and rebuild
go clean -cache
go mod download
go build -o patchleaks
```

### Language Runtime Not Found

**Problem**: `Loaded X builtin functions from fallback list`

**Impact**: This is **not an error**. PatchLeaks works perfectly with fallback lists.

**Optional Enhancement**: Install language runtimes for CLI-based extraction:
```bash
# Example for Ubuntu/Debian
sudo apt-get install php python3 ruby golang-go

# macOS
brew install php python3 ruby go
```

### Performance Issues with Large Repositories

**Problem**: Analysis is slow for large codebases

**Solutions**:
1. **Increase AI Threads**: `./patchleaks -p 8080 -t 8`
2. **Use File Filters**: Filter by file extensions in the web UI
3. **Focus on Specific Directories**: Compare subdirectories instead of entire repos
4. **Use Faster AI Service**: Ollama (local) is fastest, followed by DeepSeek

### Port Already in Use

**Problem**: `bind: address already in use`

**Solution**:
```bash
# Use a different port
./patchleaks -p 8081

# Or let PatchLeaks choose a free port automatically
./patchleaks
```

### Function Index Errors

**Problem**: `Could not build function index: ...`

**Impact**: Minor - analysis continues with regex-based fallback

**Solution**: Ensure target code files are valid and parseable for their language

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

- 🐛 **Report Bugs** — Found an issue? [Create an issue](https://github.com/hatlesswizard/patchleaks/issues)
- 💡 **Suggest Features** — Have ideas? We'd love to hear them!
- 🔧 **Submit PRs** — Code contributions are always welcome
- 📚 **Improve Docs** — Help make PatchLeaks more accessible



---

## 📄 License

PatchLeaks is released under the **GNU AGPL v3 License**. See [`LICENSE`](LICENSE) for full text.

---

## 🌟 **Star History**

[![Star History Chart](https://api.star-history.com/svg?repos=hatlesswizard/patchleaks&type=Date)](https://star-history.com/#hatlesswizard/patchleaks&Date)

---

<div align="center">

### 🚀 **Ready to revolutionize your security analysis?**

**[⭐ Star this repo](https://github.com/hatlesswizard/patchleaks/stargazers)** • **[🐛 Report issues](https://github.com/hatlesswizard/patchleaks/issues)** • **[🤝 Contribute](https://github.com/hatlesswizard/patchleaks/pulls)**

---

**Made with ❤️ by security researcher, for security researchers**

</div>
