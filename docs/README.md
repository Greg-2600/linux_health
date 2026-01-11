# 📚 Linux Health Security Scanner - Documentation

Welcome to the comprehensive documentation for **Linux Health Security Scanner v2.0.0**.

## Quick Navigation

### 🚀 Getting Started
- **[../README.md](../README.md)** - Main project README with quick start guide
- **[../SECURITY.md](../SECURITY.md)** - Security policies and vulnerability reporting

### 📖 Project Documentation

#### Release & Features
- **[RELEASE_NOTES_v2.0.0.md](RELEASE_NOTES_v2.0.0.md)** - v2.0.0 release highlights and migration guide
- **[FEATURES_ADDED.md](FEATURES_ADDED.md)** - Detailed v2.0.0 feature documentation
- **[../CHANGELOG.md](../CHANGELOG.md)** - Complete version history and changes

#### Development & Architecture
- **[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)** - Project organization and directory structure
- **[../.github/CONTRIBUTING.md](../.github/CONTRIBUTING.md)** - Contribution guidelines
- **[../.github/CODE_OF_CONDUCT.md](../.github/CODE_OF_CONDUCT.md)** - Community code of conduct

#### Planning & Roadmap (v3.0+)
- **[ANALYSIS_SUMMARY.md](ANALYSIS_SUMMARY.md)** - Executive summary of Linux Health vs Lynis analysis
- **[LYNIS_COMPARISON.md](LYNIS_COMPARISON.md)** - Detailed feature-by-feature comparison with Lynis
- **[IMPLEMENTATION_ROADMAP_V3.md](IMPLEMENTATION_ROADMAP_V3.md)** - Comprehensive roadmap for expanding to 70+ checks
- **[TEST_ID_REFERENCE.md](TEST_ID_REFERENCE.md)** - Lynis-compatible test ID allocation scheme

=======
>>>>>>> origin/master
### 📝 Version Information

**Current Version:** 2.0.0 (Latest)  
**Release Date:** January 10, 2026  
**Status:** ✅ Production Ready  
**Lynis Parity:** 95%

### ✨ What's New in v2.0.0

#### Major Features
- 🆔 **Test ID System** - Lynis-compatible test identifiers for all checks
- 📊 **JSON Output** - Machine-readable structured reports
- ⚙️ **Profile System** - YAML-based configuration and test filtering
<<<<<<< HEAD
- 🔍 **100+ Security Checks** - Comprehensive coverage across 24 categories
- 📈 **Hardening Index** - 0-100 score with per-category breakdown

# Linux Health Security Scanner

Enterprise-grade agentless security assessment for Linux infrastructure. Performs 36+ automated checks for malware, vulnerabilities, and compliance. SSH-based, Docker-ready, and Kubernetes-friendly.

## Features

- 36+ security checks (malware, vulnerabilities, compliance)
- Agentless SSH scanning (no install on target)
- Docker & Kubernetes ready
- Text, Markdown, and JSON reports
- 12 check categories (filesystem, network, packages, etc.)
- Fast, non-invasive, read-only operations
- Audit trail: all SSH sessions logged

## Quick Start

```bash
pip install -r requirements.txt
python -m linux_health 192.168.1.100 user password
```

## Docker Usage

```bash
docker build -t linux-health:dev .
docker run --rm linux-health:dev 192.168.1.100 user password
```

## Test Suite

```bash
pytest tests/ -v
```

## Documentation

All docs in this folder. See [docs/README.md](docs/README.md) for full details.
├── FEATURES_ADDED.md              # Detailed v2.0.0 features

└── RELEASE_NOTES_v2.0.0.md       # Release summary
