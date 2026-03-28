# Cybersecurity Python Portfolio
A collection of Python-based security and automation tools developed as part of my Cybersecurity curriculum. This repository demonstrates proficiency in log parsing, threat intelligence via APIs, and robust application logic.

## 📁 Project Overview

### [01. Log Analysis Tool](./01-log-analysis-tool/)
A utility for auditing system access and network security.
* **Key Features:** Extracts user authentication timestamps from `auth.log`, identifies brute-force attempts from invalid usernames, and correlates firewall blocks (`ufw.log`) with suspicious IP addresses.
* **Skills:** Regex, File I/O, Data Correlation.

### [02. NVD CVE Manager](./02-nvd-cve-manager/)
A threat intelligence tool that interacts with the NIST National Vulnerability Database.
* **Key Features:** Automated CVE retrieval via REST API, CSV data exports, and data visualization.
* **Visuals:** Generates bar charts of high-severity vulnerabilities and scatter plots comparing Exploitability vs. Severity scores.
* **Skills:** REST APIs, Data Visualization (Plotly), JSON Parsing.

### [03. Vending Machine Firmware](./03-vending-machine-firmware/)
A simulated hardware-software interface for inventory and transaction management.
* **Key Features:** Interactive CLI, JSON-based inventory tracking, automated transaction logging to CSV/SQLite, and real-time currency conversion using exchange rate APIs.
* **Skills:** Object-Oriented Programming (OOP), Unit Testing, Database Integration.

---

## 🛠️ Requirements & Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/cybersecurity-python-portfolio.git]
   (https://github.com/I-am-Bradley/cybersecurity-python-portfolio.git)
2. Install dependencies
   pip install -r requirements.txt
