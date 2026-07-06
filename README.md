# Cybersecurity Python Portfolio

## 🧭 Project Overview

### Title:
### Cybersecurity Python Portfolio

### Purpose

This repository showcases a collection of Python-based cybersecurity and automation projects developed throughout my cybersecurity coursework. The projects demonstrate practical applications of Python in security operations, threat intelligence, log analysis, API integration, data visualization, and software engineering.

### Audience

- Cybersecurity Students
- Security Analysts
- SOC Analysts
- Incident Responders
- Software Developers
- Recruiters and Hiring Managers

---

# 🧱 Project Scope

## 01. Log Analysis Tool

Analyzes Linux authentication and firewall logs to identify suspicious activity and support incident investigations.

### Components

- Authentication Log Parser
- Firewall Log Parser
- Brute Force Detection
- IP Correlation Engine

### Techniques

- Regular Expressions (Regex)
- File Parsing
- Data Correlation
- Log Analysis
- Python File I/O

---

## 02. NVD CVE Manager

Retrieves and analyzes vulnerability information directly from the National Vulnerability Database (NVD).

### Components

- NVD REST API Client
- Vulnerability Search
- CSV Export
- Visualization Dashboard

### Techniques

- REST APIs
- JSON Parsing
- Data Visualization
- Plotly
- CSV Processing

---

## 03. Vending Machine Firmware

Simulates a smart vending machine using object-oriented programming principles while demonstrating persistent storage and external API integration.

### Components

- Interactive CLI
- Inventory Management
- Transaction Logging
- Currency Conversion

### Techniques

- Object-Oriented Programming (OOP)
- SQLite
- JSON Storage
- Unit Testing
- REST APIs

---

# 📂 Repository Structure

```text
Cybersecurity_Python_Portfolio/
│
├── README.md
│
├── 01-log-analysis-tool/
│   ├── log/
│   |    ├── auth.log.1.txt
│   |    ├── auth.log.2.txt
│   |    ├── auth.log.3.txt
│   |    ├── auth.log.4.txt
│   |    ├── ufw.log.1.txt
│   |    ├── ufw.log.2.txt
│   |    ├── ufw.log.3.txt
│   |    └── ufw.log.4.txt
│   ├── src_/
│   |    └── log_analysis.py
│   ├── tests/
│   |    └── test_log_analysis.py
│   ├── .gitignore
│   └── README.md
│
├── 02-nvd-cve-manager/
│   ├── data/
│   |    ├── cve-2022-02-sample.csv
│   |    ├── cve-barplot.png
│   |    └── cve-scatter.png
│   ├── src_/
│   |    ├── nvd_cve_analysis.py
│   |    └── nvd_cve_testing.py
│   ├── tests/
│   |    ├── test_request_cve_list.py
│   |    └── test_write_CVEs_to_csv.py
│   ├── .env
│   └── README.md
│
├── requirements.txt/
│
└── .gitignore

```

---

# 🔧 Projects Included

| Project | Description | Technologies |
|---------|-------------|--------------|
| Log Analysis Tool | Parses Linux authentication and firewall logs to identify suspicious activity and brute-force attempts. | Regex, File I/O, Log Analysis |
| NVD CVE Manager | Retrieves and analyzes vulnerability information from the National Vulnerability Database. | REST APIs, JSON, Plotly |
| Vending Machine Firmware | Simulates inventory and transaction management using persistent storage and external APIs. | Python, SQLite, OOP, Unit Testing |

---

# 💻 Skills Demonstrated

- Python
- Cybersecurity
- Security Automation
- Log Analysis
- Incident Response
- Threat Intelligence
- REST API Integration
- JSON Processing
- CSV Processing
- Data Visualization
- Object-Oriented Programming
- SQLite
- Unit Testing
- File Parsing
- Regular Expressions (Regex)

---

# 🚀 Getting Started

## Clone the Repository

```bash
git clone https://github.com/I-am-Bradley/cybersecurity-python-portfolio.git
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

Each project contains its own documentation and instructions for execution.

---

# 📈 Future Improvements

- Add additional SOC automation tools
- Integrate SIEM log ingestion
- Expand threat intelligence sources
- Add malware analysis utilities
- Develop additional security dashboards

---

# 📄 Documentation

Each project includes its own documentation describing:

- Project objectives
- Installation instructions
- Usage examples
- Implementation details

---

# 📬 Author

**Bradley Titagwan**

Version: v1.0
