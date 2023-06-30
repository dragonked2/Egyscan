# Web Vulnerability Scanner

This is a simple web vulnerability scanner script that scans a target website for common vulnerabilities. It checks for SQL injection, remote code execution, cross-site scripting (XSS), local file inclusion (LFI), open redirect, backup files, database exposure, directory listings, and sensitive information exposure vulnerabilities.

## Prerequisites

- Python 3.6 or higher
- pip package manager

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/dragonked2/Egyscan.git

    Navigate to the project directory:

cd Egyscan

Install the dependencies:

bash

    pip install -r requirements.txt

Usage

    Run the script:

    bash

    python egy.py

    Enter the target URL when prompted.

    The scanner will collect URLs from the target website and scan them for vulnerabilities. Detected vulnerabilities will be displayed in the console.

Customization

    You can modify the list of payloads in the payloads variable in the script to include additional payloads for injection.

    The maximum number of concurrent workers and requests per second can be adjusted by modifying the MAX_WORKERS and REQUESTS_PER_SECOND constants, respectively.

Disclaimer

This script is provided for educational purposes only. Use it responsibly and only on websites that you have permission to scan. The authors are not responsible for any misuse or damage caused by this script.
License

This project is licensed under the MIT License.
