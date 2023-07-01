import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from itertools import islice
from urllib.robotparser import RobotFileParser
from ratelimit import limits, sleep_and_retry
from bs4 import MarkupResemblesLocatorWarning
import time
import logging
import tqdm
import warnings
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

#----------------------------------------------------------
# Project: Egyscan 
# Copyright (c) 2023 dragonked2
# This code is protected by copyright law. Unauthorized
# use or distribution is strictly prohibited.
#----------------------------------------------------------

ALLOWED_HOSTS = ["www.google.com"]

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
    sanitized_url = urljoin(url, payload)
    parsed_url = urlparse(sanitized_url)

    if parsed_url.netloc in ALLOWED_HOSTS:
        response = requests.get(sanitized_url)
        if response.status_code == 302 and urlparse(response.url).netloc == "www.google.com":
            return True

    return False

def check_backup_files(url):
    extensions = [".bak", ".zip", ".tgz"]
    parsed_url = urlparse(url)

    for extension in extensions:
        backup_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{parsed_url.path}{extension}"
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
    try:
        soup = BeautifulSoup(html, "html.parser")
        urls = set()
        for anchor in soup.find_all("a"):
            href = anchor.get("href")
            if href:
                href = urljoin(base_url, href)
                urls.add(href)
        return urls
    except bs4.FeatureNotFound:
        return set()


# Collect URLs recursively from the target website and its sub-pages
def collect_urls(target_url):
    parsed_url = urlparse(target_url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc
    urls = set()
    processed_urls = set()
    robots_parser = parse_robots_txt(target_url)

    urls.add(target_url)

    with tqdm.tqdm(total=len(urls), desc="Collecting URLs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            while urls:
                current_url = urls.pop()

                # Skip already processed URLs
                if current_url in processed_urls:
                    continue

                processed_urls.add(current_url)

                future = executor.submit(rate_limited_request, current_url)
                futures.append(future)

                # Process completed futures
                for completed_future in as_completed(futures):
                    try:
                        response = completed_future.result()
                        if response.status_code == 200:
                            extracted_urls = extract_urls_from_html(response.text, base_url)
                            filtered_urls = filter_urls(extracted_urls, parsed_url.netloc, processed_urls)
                            urls.update(filtered_urls)
                    except requests.exceptions.RequestException:
                        continue

                    pbar.update(1)

                futures = [future for future in futures if not future.done()]

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
    processed_parameters = set()
    for param in params:
        if param in processed_parameters:
            continue

        processed_parameters.add(param)

        for payload in payloads:
            injected_params = params.copy()
            param_values = injected_params.get(param)
            if param_values is not None:
                injected_params[param] = [param_value + payload for param_value in param_values]
                injected_url = url.split("?")[0] + "?" + "&".join(
                    f"{key}={value}" for key, value in injected_params.items()
                )
                scan_url(injected_url)

    # Inject payloads into form inputs
    response = requests.get(url)
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


# Scan a URL for vulnerabilities
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
        logging.warning(f"Backup Files vulnerability found: {url}")
    if check_database_exposure(url):
        logging.warning(f"Database Exposure vulnerability found: {url}")
    if check_directory_listings(url):
        logging.warning(f"Directory Listings vulnerability found: {url}")
    if check_sensitive_information(url):
        logging.warning(f"Sensitive Information exposure vulnerability found: {url}")

# Scan a response for vulnerabilities
def scan_response(response):
    if check_sqli(response.url):
        logging.warning(f"SQL Injection vulnerability found: {response.url}")
    if check_rce(response.url):
        logging.warning(f"Remote Code Execution vulnerability found: {response.url}")
    if check_xss(response.url):
        logging.warning(f"Cross-Site Scripting vulnerability found: {response.url}")
    if check_lfi(response.url):
        logging.warning(f"Local File Inclusion vulnerability found: {response.url}")
    if check_open_redirect(response.url):
        logging.warning(f"Open Redirect vulnerability found: {response.url}")
    if check_backup_files(response.url):
        logging.warning(f"Backup Files vulnerability found: {response.url}")
    if check_database_exposure(response.url):
        logging.warning(f"Database Exposure vulnerability found: {response.url}")
    if check_directory_listings(response.url):
        logging.warning(f"Directory Listings vulnerability found: {response.url}")
    if check_sensitive_information(response.url):
        logging.warning(f"Sensitive Information exposure vulnerability found: {response.url}")


def print_colorful(message, color=Fore.GREEN):
    print(color + message + Style.RESET_ALL)

def print_warning(message):
    print(Fore.YELLOW + "Warning: " + message + Style.RESET_ALL)

def print_error(message):
    print(Fore.RED + "Error: " + message + Style.RESET_ALL)

def print_info(message):
    print(Fore.BLUE + "Info: " + message + Style.RESET_ALL)

def main():
    print_colorful("EgyScan V2.0", Fore.YELLOW)
    # Get the target URL from the user
    target_url = input("Enter the target URL to scan for vulnerabilities: ")

    print_logo()
    print_colorful("EgyScan V2.0", Fore.YELLOW)

    # Collect URLs from the target website
    print_info("Collecting URLs from the target website...")
    urls = collect_urls(target_url)

    print_colorful(f"Found {len(urls)} URLs to scan.", Fore.CYAN)

    # Scan the collected URLs for vulnerabilities
    print_info("Scanning collected URLs for vulnerabilities...")
    with tqdm.tqdm(total=len(urls), desc="Scanning URLs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(scan_url, url) for url in urls]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error occurred while scanning URL: {e}")

    # Inject payloads into parameters, query, and form inputs
    print_info("Injecting payloads into parameters, query, and form inputs...")
    with tqdm.tqdm(total=len(urls), desc="Injecting Payloads", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(inject_payloads, url) for url in urls]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error occurred while injecting payloads: {e}")

    logging.info("Scanning completed!")

if __name__ == "__main__":
    main()