EgyScan V2.0
<br>
![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)


EgyScan is a vulnerability scanning tool designed to identify potential security vulnerabilities in a target website. It performs various checks for common vulnerabilities such as SQL injection (SQLi), remote code execution (RCE), cross-site scripting (XSS), local file inclusion (LFI), open redirect, backup files, database exposure, directory listings, sensitive information exposure, XML external entity (XXE) injection, server-side request forgery (SSRF), remote file inclusion (RFI), and log file disclosure.
Features
![image](https://github.com/dragonked2/Egyscan/assets/66541902/45269369-e284-4006-8fcd-d8dd0e0cfdae)


    Collects URLs from the target website
    Scans collected URLs for vulnerabilities
    Injects payloads into parameters, query strings, and form inputs
    Reports potential vulnerabilities found during the scanning process

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
