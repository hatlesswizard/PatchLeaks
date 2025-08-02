# PatchLeaks – From Patch to PoC  
🚀 **[Try PatchLeaks Live Demo](https://pwn.az) [Start with GitHub Repository Analysis](https://github.com/hatlesswizard/PatchLeaks/main/README.md#-github-repository-analysis)** 🚀

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

## 🚀 Quick Start

### 🔧 **Installation**
```bash
# Clone and setup
git clone https://github.com/hatlesswizard/patchleaks.git
cd patchleaks

# Install dependencies
pip install -r requirements.txt

# Configure AI service (edit ai_config.json)
# Add your API keys for OpenAI, Claude, or DeepSeek

# Run the application
python app.py
```

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
4. Let PatchLeaks fetch and analyze automatically
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

## 🔧 Configuration

### 🤖 **AI Provider Setup**

<details>
<summary><strong>🔸 OpenAI GPT-4</strong></summary>

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
