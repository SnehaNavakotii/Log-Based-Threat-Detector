# Automated Log-Based Threat Detection Tool

## 🛡️ Overview
The **Log-Based Threat Detection Tool** is a Python-based automation script designed to assist **Security Operations Center (SOC)** analysts. It automatically parses large volumes of server log files to identify and flag potential security threats in real-time.

Manual log analysis is time-consuming and prone to errors. This tool automates the process using pattern recognition to detect suspicious activities such as **Brute Force Attacks**, **Failed Login Attempts**, and **Unauthorized Access**, helping to secure system infrastructure.

## ✨ Key Features
* **Automated Log Parsing:** Reads and processes server logs (e.g., Apache, Nginx, System logs) line-by-line.
* **Keyword Pattern Matching:** Detects specific threat indicators using keywords like:
    * `Failed Password` / `Login Failed`
    * `Unauthorized` / `Access Denied`
    * `Error 403` / `Error 500`
* **IP Address Extraction:** Identifies and extracts the Source IP addresses associated with suspicious activities.
* **Severity Classification:** Categorizes logs based on threat levels (Low, Medium, High).
* **Summary Reporting:** Generates a concise report highlighting total threats found and top attacking IPs.

## 🛠️ Tech Stack
* **Language:** Python 3.x
* **Core Modules:**
    * `re` (Regular Expressions): For advanced pattern matching and IP extraction.
    * `os`: For file handling and directory navigation.
    * `datetime`: For timestamp analysis.

## ⚙️ How It Works
1.  **Input:** The user provides the path to the log file (e.g., `server_logs.txt`).
2.  **Scanning:** The script iterates through the file, applying Regular Expressions (RegEx) to match defined threat patterns.
3.  **Correlation:** It counts repeated failed attempts from the same IP address (simulating Brute-Force detection).
4.  **Alerting:** Suspicious lines are flagged and displayed on the console with timestamps.
5.  **Output:** A summary report is saved, listing all flagged events for further investigation.

## 📦 Installation & Usage
1.  Clone this repository:
    ```bash
    git clone [https://github.com/SnehaNavakotii/Log-Based-Threat-Detector.git](https://github.com/SnehaNavakotii/Log-Based-Threat-Detector.git)
    ```
2.  Navigate to the directory:
    ```bash
    cd Log-Based-Threat-Detector
    ```
3.  Run the script with a sample log file:
    ```bash
    python main.py
    ```

## ⚠️ Disclaimer
This tool is developed for **Educational Purposes and Internal Security Auditing**. It is designed to analyze logs owned by the user. Unauthorized analysis of third-party data is strictly prohibited.

---
**Developed by:** Sneha Latha Navakoti
**Role:** CyberSecurity Enthusiast & Python Developer
