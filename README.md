EgyScan V2.0
<br>
![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)
![Github License](https://img.shields.io/badge/license-GPLv3-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
<p align="center">

EgyScan is a vulnerability scanning tool designed to identify potential security vulnerabilities in a target website. It performs various checks for common vulnerabilities such as SQL injection (SQLi), remote code execution (RCE), cross-site scripting (XSS), local file inclusion (LFI), open redirect, backup files, database exposure, directory listings, sensitive information exposure, XML external entity (XXE) injection, server-side request forgery (SSRF), remote file inclusion (RFI), and log file disclosure.
Features
![image](https://github.com/dragonked2/Egyscan/assets/66541902/5019ee3c-1965-4761-8ce2-84e0ec40751f)



Protect your website from vulnerabilities with our advanced security scanning tool! Here are the key vulnerabilities we help you address:

    SQL Injection (SQLI) - Prevent attacks that compromise your database integrity.
    Remote Code Execution (RCE) - Stay ahead of hackers and safeguard against unauthorized access.
    Cross-Site Scripting (XSS) - Protect your users' sensitive information from exploitation.
    Local File Inclusion (LFI) - Secure critical files and prevent confidential information exposure.
    Open Redirect - Eliminate vulnerabilities that allow attackers to misdirect users.
    Backup File Exposure - Locate and secure backup files to avoid accidental data leaks.
    Database Exposure - Detect potential database exposure, including exposed admin interfaces.
    Directory Listings - Prevent the disclosure of your website's directory structure.
    Sensitive Information Exposure - Safeguard private keys, API credentials, and other sensitive data.
    XML External Entity (XXE) - Identify and mitigate vulnerabilities that could lead to data leaks.
    Server-Side Request Forgery (SSRF) - Bolster defenses against attacks attempting to bypass security measures.
    Remote File Inclusion (RFI) - Detect and address vulnerabilities that allow unauthorized access.
    Log File Disclosure - Preserve the confidentiality of log files and protect sensitive data.

Don't leave your website vulnerable to these threats. Contact us today to fortify your defenses and ensure the security of your valuable data!
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
