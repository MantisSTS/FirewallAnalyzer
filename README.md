# 🔒 Firewall Security Auditor

A Python tool for auditing firewall configurations and identifying security vulnerabilities.

## ✨ Features

- **120+ Security Checks** - Comprehensive vulnerability detection across multiple categories
- **CVSS 3.1 Scoring** - Industry-standard risk assessment for each finding
- **Multiple Input Formats** - Supports text config files and CSV policy exports
- **Rich HTML Reports** - Professional reports with risk summaries and detailed findings
- **Multi-Occurrence Tracking** - Logs all instances of security issues with line numbers
- **Firewall Identification** - Automatically extracts firewall names from configurations

## 🚀 Quick Start

```bash
# Audit a single configuration file
python audit.py --files config.txt --output my_audit --verbose

# Audit multiple files with wildcards
python audit.py --files "*.txt" --output comprehensive_audit --verbose

# Audit CSV policy exports
python audit.py --files "policies.csv" --output policy_audit --verbose
```

## 📊 Security Categories

- **Administrative Controls** - SSH, Telnet, timeouts, authentication, account security
- **SSL/TLS Security** - Certificate validation, encryption protocols, weak hashes
- **Network Security** - Firewall rules, VPN settings, SNMP configuration
- **Access Control** - Password policies, login restrictions, banners, MFA
- **Logging & Monitoring** - Traffic logging, audit settings, FortiLog
- **System Hardening** - USB ports, services, protocols, firmware updates
- **Wireless Security** - WEP/WPA settings, WPS, SSID broadcasting
- **Content Security** - Layer 7 filtering, IPS/IDS, application control
- **Operating System** - Version checks, update policies, security patches

## 📋 Output

- **HTML Report** - Comprehensive visual report with risk assessment
- **JSON Data** - Machine-readable output for integration
- **Console Summary** - Quick overview of findings and risk levels

## 🎯 Risk Levels

- 🔴 **Critical** (9.0-10.0) - Immediate action required
- 🟠 **High** (7.0-8.9) - High priority remediation
- 🟡 **Medium** (4.0-6.9) - Moderate risk issues
- 🟢 **Low** (0.0-3.9) - Minor improvements

## 📄 Requirements

- Python 3.6+
- Standard library only (no external dependencies)

---

*Built for security professionals to streamline firewall configuration reviews and compliance audits.*
