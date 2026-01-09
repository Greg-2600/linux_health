# Changelog

All notable changes to Linux Health Security Scanner are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-09

### Added

**Core Features**
- ✨ 36+ comprehensive security assessments across 12 security domains
- 🔒 Agentless SSH-based scanning (no agent installation required)
- 🎯 Advanced threat detection (reverse shells, crypto miners, rootkits)
- 📊 Vulnerability assessment (privilege escalation, weak configurations)
- 💻 System health monitoring (disk, memory, CPU, processes)
- 📋 Professional reporting in text and Markdown formats
- 🐳 Full Docker and Kubernetes support
- ⚙️ Configurable timeouts for high-latency networks

**Security Checks**
- Malware/backdoor detection (reverse shells, miners, rootkits)
- Privilege escalation vector identification
- Weak password policy detection
- Container escape indicator scanning
- Network security analysis (ARP spoofing, DNS tampering)
- File integrity monitoring (SUID binaries, world-writable files)
- Log tampering detection
- Suspicious network connection tracking

**Testing & Quality**
- 107 comprehensive unit tests (100% pass rate)
- 66% code coverage (100% on critical modules)
- Zero linting errors (ruff + black)
- Production-ready code quality

**Documentation**
- Professional README with 15+ sections
- Quick start guide
- Complete security check reference
- Docker deployment guide
- Development guide with examples
- Integration examples (Ansible, Nagios, Kubernetes)

**Integration**
- Docker and Docker Compose support
- Kubernetes CronJob examples
- Ansible playbook examples
- Nagios/Icinga plugin examples

---

## Future Roadmap

### [1.1.0] (Planned)
- Configuration file support (`.linuxhealth.json`)
- Baseline comparison mode (detect changes)
- Results database export (JSON/CSV)
- Custom check plugin system
- Parallel check execution
- Multi-host orchestration script

### [1.2.0] (Planned)
- SSH key-based authentication (optional password-less auth)
- Results caching for repeated scans
- Detailed remediation guidance expansion
- Helm chart for Kubernetes deployment
- Integration with Prometheus metrics

### [2.0.0] (Future)
- Agent-based scanning mode (optional)
- Windows system support
- Cloud platform scanning (AWS, Azure, GCP)
- REST API for integrations
- Web-based dashboard

---

## How to Upgrade

### From v0.x to v1.0.0

No breaking changes! All v0.x commands work with v1.0.0:

```bash
pip install --upgrade linux-health
```

Then use as normal:

```bash
python -m linux_health host user password
```

---

## Security Advisory

### Version 1.0.0 Security Status
- ✅ All dependencies audited
- ✅ No known vulnerabilities
- ✅ Read-only operations only
- ✅ SSH over encrypted connections

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## Contributors

Thanks to all contributors who made this release possible!

- **Greg B** - Lead Developer
- **Community Feedback** - Alpha testing and suggestions

---

## Support

- 📖 **Documentation:** See [README.md](README.md)
- 🐛 **Report Bugs:** [GitHub Issues](https://github.com/yourusername/linux_health/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/yourusername/linux_health/discussions)
- 🔒 **Security:** See [SECURITY.md](SECURITY.md)

---

[1.0.0]: https://github.com/yourusername/linux_health/releases/tag/v1.0.0
