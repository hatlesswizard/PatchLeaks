# PatchLeaks – From Patch to PoC  
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

## Key Features
- **Folder Analysis** — Compare any two local directories  
- **Product Analysis** — Use public GitHub repository directly; PatchLeaks fetches, compares, and reports.
- **CVE Mode** — Paste a CVE ID, choose affected version with patched version, and let the engine spot the patch
- **Keyword Scoping** — Limit attention to particular file extensions
- **Reports** — Save, reopen, and share analyses; every run is reproducible.
- **Pluggable Back-Ends** — Works with both self and cloud hosted AI models.


---

## Reports

| View          | What You Get                                                     |
| :------------ | :--------------------------------------------------------------- |
| **Dashboard** | checked repos', vulnerability counts, and models used.           |
| **File Diff** | Side-by-side patches with inline reasoning                       |
| **Search**    | Keyword & CVE filters across all saved analyses                  |
| **Share**     | Save your analysis sessions and share findings with your team via a unique link. |


---

## License

PatchLeaks is released under the GNU AGPL v3 License. See [`LICENSE`](LICENSE) for full text.
