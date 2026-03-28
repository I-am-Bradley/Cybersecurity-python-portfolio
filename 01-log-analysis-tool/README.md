# Project 1: Linux Log Analysis & Security Auditing

This tool automates the process of auditing Linux system logs to identify potential security threats, such as brute-force attacks and unauthorized access attempts. By correlating authentication logs with firewall data, it provides a clear picture of suspicious network activity.

---

## 🛠 Features

### 1. User Authentication Tracking
The `get_user_auth_times(user_id)` function parses rotated authentication logs (`auth.log.x`) to extract specific login timestamps for a target user. This is critical for building a timeline of user activity during an incident response.

### 2. Brute-Force Detection
The `get_invalid_logins()` function scans logs for "Invalid User" entries. It generates a frequency dictionary of attempted usernames, helping security analysts identify common credential-stuffing targets (e.g., `admin`, `root`, `mysql`).

### 3. Firewall Correlation
The `compare_invalid_IPs()` function performs a cross-analysis between:
* **Authentication Logs:** IP addresses attempting invalid logins.
* **UFW Logs:** IP addresses blocked by the Uncomplicated Firewall.

This identifies high-risk actors who are actively attempting to bypass both network-level and application-level security controls.

---

## 📊 Sample Output

When executed against standard system logs, the tool provides the following insights:

**User Login Timeline:**
> `['Feb 21 13:29:56', 'Feb 21 13:36:38', 'Feb 21 13:33:56']`

**Invalid Username Frequency:**
> `{'admin': 17, 'user': 244, 'guest': 3, ...}`

**High-Risk IP Correlation (Blocked + Invalid Login):**
> `{'141.98.11.23', '45.9.20.73', '64.62.197.182', ...}`

---

## 🚀 Technical Skills Demonstrated
* **Log Parsing:** Efficiently handling rotated log files (`.log.x`) using Python's `glob` and `re` modules.
* **Data Structures:** Using dictionaries and sets to perform $O(1)$ lookups and find intersections between large data sets.
* **Security Auditing:** Deep understanding of the structure of `/var/log/auth.log` and `/var/log/ufw.log` for threat detection.

---

## 📂 Setup & Usage
1. Ensure your log files are located in a `log/` directory relative to the script.
2. Run the analyzer:
   ```bash
   python3 log_analyzer.py
