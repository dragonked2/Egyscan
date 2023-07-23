# EgyScan V2.0

[![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Github License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)

<p align="center">
  <img src="https://github.com/dragonked2/Egyscan/assets/66541902/c769777f-7e6a-4d1f-8907-bb4e75c8d01e" alt="EgyScan Logo">
</p>

## Protect Your Website from Vulnerabilities with EgyScan

EgyScan is an advanced vulnerability scanning tool designed to identify potential security risks in your website. Our comprehensive scanning capabilities help you address key vulnerabilities, ensuring the protection of your valuable data.

## Key Features

- **Thorough Scanning**: EgyScan performs a wide range of checks to identify common vulnerabilities, including:
  
  - SQL Injection
  - Remote Code Execution
  - Cross-Site Scripting (XSS)
  - Local File Inclusion (LFI)
  - Open Redirect
  - Backup Files
  - Database Exposure
  - Directory Listings
  - Sensitive Information Exposure
  - XML External Entity (XXE) Injection
  - Server-Side Request Forgery (SSRF)
  - Remote File Inclusion (RFI)
  - Log File Disclosure
  - Insecure Direct Object Reference (IDOR)
  - Cross-Origin Resource Sharing (CORS)
  - Cross-Site Request Forgery (CSRF)
  - Command Injection
  - File Upload Vulnerabilities
  - Authentication Bypass
  - Insecure Configuration
  - Server Misconfiguration
  - Injection Flaws
  - Weak Session Management
  - Clickjacking
  - Host Header Injection
  - Remote File Execution
  - Brute Force Attacks
  - Security Misconfiguration
  - Missing Authentication
  - CRLF Injection
  - Session Fixation
  - Unvalidated Redirects
  - Command Execution
  - Cross-Site Tracing
  - Server-Side Template Injection
  - File Inclusion
  - Privilege Escalation
  - XML Injection
  - Weak Cryptography
  - Deserialization Vulnerabilities
  - Server-Side Request Forgery (SSRF)
  
- **URL Collection**: EgyScan collects URLs from your target website by crawling web pages and extracting links.

- **Payload Injection**: The tool injects payloads into parameters, query strings, and form inputs of the collected URLs to test for vulnerabilities.

- **Multithreading**: EgyScan utilizes a thread pool to parallelize scanning and payload injection processes, enhancing performance.

- **User-Agent Randomization**: The tool randomly selects a User-Agent header from a predefined list for each HTTP request, aiding in bypassing certain security measures.

- **Logging and Output**: EgyScan logs scanning results with different log levels (INFO, WARNING, ERROR) and provides colorful output for improved readability.

Don't leave your website vulnerable to threats. Contact us today to fortify your defenses and ensure the security of your valuable data!
![image](https://github.com/dragonked2/Egyscan/assets/66541902/02de4e3a-d571-4d90-afad-e9966e44057e)

## Requirements

- Python 3.x
- requests library
- bs4 (BeautifulSoup) library
- colorama library
- tqdm library
- aiohttp

## Installation

1. Clone the repository:

   ```shell
   git clone https://github.com/dragonked2/Egyscan.git
   ```

2. Install the required dependencies:

   ```shell
   pip install -r requirements.txt
   ```

## Usage

1. Run the tool:

   ```shell
   python egy.py
   ```

2. Enter the target URL to scan for vulnerabilities.

## Disclaimer

This tool is intended for educational purposes only. Use it responsibly and only on websites that you have permission to test.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributions

Contributions to improve and enhance the tool are welcome. Feel free to submit issues and pull requests.

## Acknowledgments

EgyScan V2.0 was developed by [AliElTop].

---

[![Sponsor](https://img.shields.io/badge/sponsor-project_name-orange.svg)](https://github.com/sponsors/dragonked2)
[![Star](https://img.shields.io/badge/star-project_name-yellow.svg)](https://github.com/dragonked2/Egyscan)
