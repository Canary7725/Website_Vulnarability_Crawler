import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
from concurrent.futures import ThreadPoolExecutor
import threading

def check_http_headers(headers, url):
    vulnerabilities = []
    if 'X-Content-Type-Options' not in headers:
        vulnerabilities.append(("Missing X-Content-Type-Options header", url))
    if 'Strict-Transport-Security' not in headers:
        vulnerabilities.append(("Missing Strict-Transport-Security header", url))
    return vulnerabilities

def check_forms(forms, url):
    vulnerabilities = []
    for form in forms:
        if not form.get('action'):
            vulnerabilities.append(("Form with missing action attribute", url))
        if form.get('method', '').lower() != 'post':
            vulnerabilities.append(("Form using method other than POST", url))
    return vulnerabilities

def is_outdated_version(text, url):
    outdated_patterns = [
        re.compile(r'WordPress\s+v?([0-4]\.\d+)', re.IGNORECASE),
        re.compile(r'Apache\s+v?([0-2]\.[0-9]+)', re.IGNORECASE)
    ]
    for pattern in outdated_patterns:
        if pattern.search(text):
            return [("Possible outdated software detected", url)]
    return []

def fetch_sitemap_urls(sitemap_url, crawled_pages, processed_sitemaps):
    """
    Fetches and parses the sitemap.xml file for the given base URL.
    Handles nested sitemaps and prevents infinite loops.
    """
    urls = []
    try:
        if sitemap_url in processed_sitemaps:
            return urls

        processed_sitemaps.add(sitemap_url)
        response = requests.get(sitemap_url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, features="xml")
        for loc in soup.find_all("url"):
            url_loc = loc.find("loc")
            if url_loc:
                url = url_loc.text.strip()
                if url not in crawled_pages:
                    urls.append(url)
                    crawled_pages.add(url)

        for sitemap in soup.find_all("sitemap"):
            nested_loc = sitemap.find("loc")
            if nested_loc:
                nested_sitemap = nested_loc.text.strip()
                urls.extend(fetch_sitemap_urls(nested_sitemap, crawled_pages, processed_sitemaps))

    except requests.RequestException as e:
        print(f"Failed to fetch sitemap.xml from {sitemap_url}: {e}")
    except Exception as e:
        print(f"An error occurred while parsing sitemap.xml: {e}")
    return urls

def fetch_links_from_page(base_url, crawled_pages):
    """
    Crawls the website starting from the base URL, extracting all unique <a> tag links.
    """
    print(f"Crawling links from {base_url}...")
    urls = []
    try:
        response = requests.get(base_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        for a_tag in soup.find_all('a', href=True):
            link = urljoin(base_url, a_tag['href'].strip())
            parsed_link = urlparse(link)
            if parsed_link.netloc == urlparse(base_url).netloc and link not in crawled_pages:
                urls.append(link)
                crawled_pages.add(link)

    except requests.RequestException as e:
        print(f"Failed to fetch links from {base_url}: {e}")
    return urls

def scan_page(url, crawled_pages, vulnerabilities, lock):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to fetch {url}: {e}")
        return

    soup = BeautifulSoup(response.content, 'html.parser')

    # Check for HTTP header issues
    with lock:
        vulnerabilities.extend(check_http_headers(response.headers, url))

    # Check for outdated software
    with lock:
        vulnerabilities.extend(is_outdated_version(response.text, url))

    # Check forms
    forms = soup.find_all('form')
    with lock:
        vulnerabilities.extend(check_forms(forms, url))

def generate_report(vulnerabilities):
    if not vulnerabilities:
        print("No vulnerabilities found!")
    else:
        print("Vulnerability Report:")
        for i, (vuln, url) in enumerate(vulnerabilities, 1):
            print(f"{i}. {vuln} (URL: {url})")

def main():
    start_url = input("Enter the URL to scan: ").strip()
    crawled_pages = set()
    processed_sitemaps = set()  # Set to track processed sitemap URLs
    vulnerabilities = []
    lock = threading.Lock()

    # Fetch URLs from sitemap.xml
    print("Checking for sitemap.xml...")
    sitemap_urls = fetch_sitemap_urls(urljoin(start_url, "/sitemap.xml"), crawled_pages, processed_sitemaps)

    if sitemap_urls:
        print(f"Found {len(sitemap_urls)} URLs in sitemap.xml.")
    else:
        print("Sitemap.xml is empty or not found. Falling back to <a> tag crawling.")
        sitemap_urls = fetch_links_from_page(start_url, crawled_pages)

    def crawl_worker(url):
        scan_page(url, crawled_pages, vulnerabilities, lock)

    print(f"Starting scan on {start_url}...\n")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(crawl_worker, url) for url in sitemap_urls]
        for future in futures:
            future.result()

    generate_report(vulnerabilities)

if __name__ == "__main__":
    main()
