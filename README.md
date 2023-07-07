EgyScan V2.0
<br>
![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)
![Github License](https://img.shields.io/badge/license-GPLv3-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
<p align="center">

EgyScan is a vulnerability scanning tool designed to identify potential security vulnerabilities in a target website. It performs various checks for common vulnerabilities such as SQL injection (SQLi), remote code execution (RCE), cross-site scripting (XSS), local file inclusion (LFI), open redirect, backup files, database exposure, directory listings, sensitive information exposure, XML external entity (XXE) injection, server-side request forgery (SSRF), remote file inclusion (RFI), and log file disclosure.
Features
![image](https://github.com/dragonked2/Egyscan/assets/66541902/45269369-e284-4006-8fcd-d8dd0e0cfdae)


    Vulnerability Checks: The script checks for various vulnerabilities in the target website, including:
    SQL Injection (SQLI)
    Cross-Site Scripting (XSS)
    Local File Inclusion (LFI)
    Open Redirect
    Backup File Exposure
    Database Exposure (phpMyAdmin, Adminer, dbadmin)
    Directory Listings
    Sensitive Information Exposure (e.g., private keys, credit card numbers)
    XML External Entity (XXE)
    Server-Side Request Forgery (SSRF)
    Remote File Inclusion (RFI)
    Log File Disclosure

    URL Collection: The script collects URLs from the target website by crawling the web pages and extracting links.

    Payload Injection: The script injects payloads into the parameters, query strings, and form inputs of the collected URLs to test for vulnerabilities.

    Multithreading: The script uses a thread pool to parallelize the scanning and payload injection processes, which helps improve performance.

    User-Agent Randomization: The script randomly selects a User-Agent header from a predefined list of user agents for each HTTP request, which can help bypass certain security measures.

    Logging and Output: The script logs the scanning results using different log levels (INFO, WARNING, ERROR) and provides colorful output for better readability.

    User Interaction: The script prompts the user to enter the target URL and displays a logo and information about the tool.

Requirements

    Python 3.x
    requests library
    bs4 (BeautifulSoup) library
    colorama library
    tqdm library

Installation

    Clone the repository:

    shell

git clone https://github.com/dragonked2/Egyscan.git

Install the required dependencies:

shell

    pip install -r requirements.txt

Usage

    Run the tool:

    shell

    python egy.py

    Enter the target URL to scan for vulnerabilities.

Disclaimer

This tool is intended for educational purposes only. Use it responsibly and only on websites that you have permission to test.
License

This project is licensed under the MIT License. See the LICENSE file for details.
Contributions

Contributions to improve and enhance the tool are welcome. Feel free to submit issues and pull requests.
Acknowledgments

    EgyScan V2.0 was developed by [AliElTop].
