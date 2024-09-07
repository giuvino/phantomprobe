import subprocess
import json
import os
from typing import List, Set, Dict
import socket
import concurrent.futures
import requests
from requests.exceptions import RequestException
import dns.resolver
import whois
from github import Github
import shodan
import re
from urllib.parse import urlparse, urljoin
import dns.reversename
import time
import ipaddress
import base64
import argparse
from visualize_report import create_visual_report  # Import the visualization function


# You'll need to install these libraries:
# pip install dnspython python-whois PyGithub shodan requests

# Replace with your actual API keys
SHODAN_API_KEY = "your_api_key"
GITHUB_API_KEY = "your_api_key"

def load_api_keys():
    global SHODAN_API_KEY, GITHUB_API_KEY
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    GITHUB_API_KEY = os.getenv("GITHUB_API_KEY")
    
    if not all([SHODAN_API_KEY, GITHUB_API_KEY]):
        print("Warning: One or more API keys are missing. Some functionality may be limited.")

def display_banner():
    banner = r"""
     ▒█▀▀█ █░░█ █▀▀█ █▀▀▄ ▀▀█▀▀ █▀▀█ █▀▄▀█ ▒█▀▀█ █▀▀█ █▀▀█ █▀▀▄ █▀▀
     ▒█▄▄█ █▀▀█ █▄▄█ █░░█ ░░█░░ █░░█ █░▀░█ ▒█▄▄█ █▄▄▀ █░░█ █▀▀▄ █▀▀
     ▒█░░░ ▀░░▀ ▀░░▀ ▀░░▀ ░░▀░░ ▀▀▀▀ ▀░░░▀ ▒█░░░ ▀░▀▀ ▀▀▀▀ ▀▀▀░ ▀▀▀
                                                                      
           Passive Reconnaissance and Information Gathering Tool
    """
    print(banner)
    print("\nInitializing PhantomProbe...\n")

def run_command(command: List[str]) -> str:
    """Run a shell command and return its output."""
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

def passive_dns(domain: str) -> Set[str]:
    """Perform passive DNS enumeration using DNS queries."""
    subdomains = set()
    
    # Try to get NS records
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            subdomains.add(str(ns).rstrip('.'))
    except dns.exception.DNSException:
        pass

    # Try to get MX records
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            subdomains.add(str(mx.exchange).rstrip('.'))
    except dns.exception.DNSException:
        pass

    # Try to get TXT records
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for txt in txt_records:
            # Look for subdomains in TXT records
            potential_subdomains = re.findall(r'([a-zA-Z0-9_-]+\.{})'.format(domain), str(txt))
            subdomains.update(potential_subdomains)
    except dns.exception.DNSException:
        pass

    return subdomains

def amass(domain: str) -> Set[str]:
    """Run amass in passive mode."""
    # Replace with actual passive mode command for amass
    output = run_command(["amass", "enum", "-passive", "-d", domain])
    return set(output.splitlines())

def subfinder(domain: str) -> Set[str]:
    """Run subfinder in passive mode."""
    # Replace with actual passive mode command for subfinder
    output = run_command(["subfinder", "-d", domain, "-silent"])
    return set(output.splitlines())

def bbot(domain: str) -> Set[str]:
    """Run bbot in passive mode."""
    # Replace with actual passive mode command for bbot
    output = run_command(["bbot", "-t", domain, "-f subdomain-enum" "-rf passive"])
    return set(output.splitlines())

def enumerate_subdomains(domain: str) -> Set[str]:
    """Run all tools and combine results."""
    results = set()
    results.update(passive_dns(domain))
    results.update(amass(domain))
    results.update(subfinder(domain))
    results.update(bbot(domain))
    return results

def get_dns_records(domain: str) -> Dict[str, List[str]]:
    """Get various DNS records for the domain."""
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    results = {}
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
        except dns.exception.DNSException:
            results[record_type] = []
    return results

def analyze_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Analyze headers for useful information."""
    interesting_headers = {}
    headers_of_interest = [
        'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
        'X-Generator', 'X-Drupal-Cache', 'X-Varnish', 'Via', 'X-Web-Server',
        'X-Powered-CMS', 'X-Content-Encoded-By', 'Strict-Transport-Security',
        'Content-Security-Policy', 'X-Frame-Options', 'X-XSS-Protection'
    ]
    for header in headers_of_interest:
        if header.lower() in headers:
            interesting_headers[header] = headers[header.lower()]
    return interesting_headers

def fingerprint_web_application(headers: Dict[str, str], html_content: str = "") -> Dict[str, str]:
    """Fingerprint web application based on HTTP headers and HTML content."""
    fingerprints = {}

    # Header-based fingerprinting
    header_patterns = {
        "Server": {
            "Apache": r"Apache/?([0-9.]*)",
            "Nginx": r"nginx/?([0-9.]*)",
            "IIS": r"Microsoft-IIS/([0-9.]*)",
            "LiteSpeed": r"LiteSpeed/?([0-9.]*)",
        },
        "X-Powered-By": {
            "PHP": r"PHP/([0-9.]*)",
            "ASP.NET": r"ASP\.NET",
        },
        "X-AspNet-Version": {
            ".NET Framework": r"([0-9.]*)",
        },
    }

def analyze_email_security(domain: str, dns_records: Dict[str, List[str]]) -> Dict[str, any]:
    """Analyze email security based on DNS records."""
    mx_records = dns_records.get('MX', [])
    txt_records = dns_records.get('TXT', [])
    
    spf_record = next((record for record in txt_records if record.startswith('v=spf1')), None)
    dmarc_record = get_dmarc_record(domain)
    
    return {
        "mx_records": mx_records,
        "spf": {"exists": bool(spf_record), "record": spf_record},
        "dmarc": dmarc_record
    }

def get_dmarc_record(domain: str) -> Dict[str, any]:
    """Get and parse DMARC record."""
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        dmarc_record = next((str(rdata) for rdata in answers if str(rdata).startswith('v=DMARC1')), None)
        if dmarc_record:
            return {"exists": True, "record": dmarc_record}
        return {"exists": False}
    except dns.exception.DNSException:
        return {"exists": False}

def get_whois_info(domain: str) -> Dict[str, any]:
    """Get WHOIS information for the domain."""
    try:
        w = whois.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
    except Exception:
        return {}

def search_github(domain: str) -> List[Dict[str, str]]:
    """Search for public GitHub repositories associated with the domain."""
    g = Github(GITHUB_API_KEY)
    repos = g.search_repositories(query=f"'{domain}' in:readme OR '{domain}' in:description")
    return [{"name": repo.name, "url": repo.html_url} for repo in repos[:5]]  # Limit to top 5 results

def check_shodan(ip: str) -> Dict[str, any]:
    """Check Shodan for information about the IP."""
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        results = api.host(ip)
        return {
            "os": results.get('os', 'Unknown'),
            "ports": results.get('ports', []),
            "vulns": results.get('vulns', [])
        }
    except shodan.APIError:
        return {}

def fingerprint_web_application(headers: Dict[str, str], html_content: str = "") -> Dict[str, str]:
    """Fingerprint web application based on HTTP headers and HTML content."""
    fingerprints = {}

    # Header-based fingerprinting
    header_patterns = {
        "Server": {
            "Apache": r"Apache/?([0-9.]*)",
            "Nginx": r"nginx/?([0-9.]*)",
            "IIS": r"Microsoft-IIS/([0-9.]*)",
            "LiteSpeed": r"LiteSpeed/?([0-9.]*)",
        },
        "X-Powered-By": {
            "PHP": r"PHP/([0-9.]*)",
            "ASP.NET": r"ASP\.NET",
        },
        "X-AspNet-Version": {
            ".NET Framework": r"([0-9.]*)",
        },
    }

    for header, patterns in header_patterns.items():
        if header.lower() in headers:
            for tech, pattern in patterns.items():
                match = re.search(pattern, headers[header.lower()], re.IGNORECASE)
                if match:
                    fingerprints[tech] = match.group(1) if match.groups() else "Detected"

    # HTML-based fingerprinting
    html_patterns = {
        "WordPress": r"<meta name=[\"']generator[\"'] content=[\"']WordPress ?([0-9.]+)",
        "Joomla": r"<meta name=[\"']generator[\"'] content=[\"']Joomla! - Open Source Content Management",
        "Drupal": r"<meta name=[\"']Generator[\"'] content=[\"']Drupal ([0-9.]+)",
        "Shopify": r"<meta name=[\"']generator[\"'] content=[\"']Shopify",
        "Magento": r"<script type=[\"']text/x-magento-init",
        "PrestaShop": r"<meta name=[\"']generator[\"'] content=[\"']PrestaShop",
        "OpenCart": r"<meta name=[\"']generator[\"'] content=[\"']OpenCart",
        "Wix": r"<meta name=[\"']generator[\"'] content=[\"']Wix\.com Website Builder",
        "Squarespace": r"<meta name=[\"']generator[\"'] content=[\"']Squarespace",
    }

    for tech, pattern in html_patterns.items():
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            fingerprints[tech] = match.group(1) if match.groups() else "Detected"

    # JavaScript library detection
    js_patterns = {
        "jQuery": r"jquery[.-]([0-9.]+)\.min\.js",
        "React": r"react[.-]([0-9.]+)\.min\.js",
        "Vue.js": r"vue[.-]([0-9.]+)\.min\.js",
        "Angular": r"angular[.-]([0-9.]+)\.min\.js",
        "Bootstrap": r"bootstrap[.-]([0-9.]+)\.min\.",
    }

    for tech, pattern in js_patterns.items():
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            fingerprints[tech] = match.group(1)

    # Additional framework and technology detection
    if re.search(r"laravel", html_content, re.IGNORECASE):
        fingerprints["Laravel"] = "Detected"
    if re.search(r"django", html_content, re.IGNORECASE):
        fingerprints["Django"] = "Detected"
    if re.search(r"rails", html_content, re.IGNORECASE):
        fingerprints["Ruby on Rails"] = "Detected"
    if re.search(r"nextjs", html_content, re.IGNORECASE):
        fingerprints["Next.js"] = "Detected"
    if re.search(r"gatsby", html_content, re.IGNORECASE):
        fingerprints["Gatsby"] = "Detected"

    vulnerable_libs = check_vulnerable_js_libraries(html_content)
    fingerprints.update(vulnerable_libs)

    return fingerprints


def passive_content_discovery(url: str, html_content: str, headers: Dict[str, str]) -> Set[str]:
    """Perform passive content discovery based on HTML content and headers."""
    discovered_content = set()

    # Extract links from HTML
    links = re.findall(r'href=[\'"]?(/[^\'" >]+)', html_content)
    discovered_content.update(links)

    # Extract src attributes (for scripts, images, etc.)
    src_attrs = re.findall(r'src=[\'"]?(/[^\'" >]+)', html_content)
    discovered_content.update(src_attrs)

    # Look for potential API endpoints
    api_patterns = [r'/api/\w+', r'/v1/\w+', r'/v2/\w+', r'/rest/\w+']
    for pattern in api_patterns:
        api_endpoints = re.findall(pattern, html_content)
        discovered_content.update(api_endpoints)

    # Check for common admin panels
    admin_panels = ['/admin', '/administrator', '/wp-admin', '/dashboard', '/cpanel']
    discovered_content.update(admin_panels)

    # Check for common file types
    file_types = ['.php', '.asp', '.aspx', '.jsp', '.js', '.css', '.xml', '.json']
    for file_type in file_types:
        files = re.findall(r'/\w+\{}'.format(file_type), html_content)
        discovered_content.update(files)

    # Extract paths from JavaScript (basic approach)
    js_paths = re.findall(r'[\'"/][a-zA-Z0-9_/.?=&-]+', html_content)
    discovered_content.update(js_paths)

    # Look for potential subdomains in content
    subdomains = re.findall(r'(https?://([a-zA-Z0-9.-]+))', html_content)
    discovered_content.update([sub[0] for sub in subdomains])

    # Check headers for potential paths
    for header, value in headers.items():
        if 'path' in header.lower():
            discovered_content.add(value)

    # Normalize and filter discovered content
    base_url = urlparse(url).scheme + "://" + urlparse(url).netloc
    normalized_content = set()
    for path in discovered_content:
        if path.startswith('http'):
            normalized_content.add(path)
        elif path.startswith('/'):
            normalized_content.add(urljoin(base_url, path))
        else:
            normalized_content.add(urljoin(base_url, '/' + path))

    return normalized_content

def check_vulnerable_js_libraries(html_content: str) -> Dict[str, str]:
    """Check for potentially vulnerable JavaScript libraries."""
    vulnerable_libraries = {}
    
    # Define patterns for common libraries and their versions
    library_patterns = {
        "jQuery": r'jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
        "Angular": r'angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
        "React": r'react[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
        "Vue.js": r'vue[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
        "Lodash": r'lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
        "Moment.js": r'moment[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
        "Bootstrap": r'bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.js',
    }

    # Known vulnerable versions (this is a simplified list and should be regularly updated)
    known_vulnerabilities = {
        "jQuery": [
            {"version": "1.9.0", "vulnerability": "XSS vulnerability (CVE-2012-6708)"},
            {"version": "3.4.0", "vulnerability": "Prototype pollution (CVE-2019-11358)"},
        ],
        "Angular": [
            {"version": "1.6.0", "vulnerability": "XSS vulnerability (CVE-2018-14879)"},
        ],
        "Lodash": [
            {"version": "4.17.11", "vulnerability": "Prototype pollution (CVE-2019-10744)"},
        ],
        # Add more known vulnerabilities for other libraries
    }

    for library, pattern in library_patterns.items():
        matches = re.findall(pattern, html_content)
        if matches:
            version = matches[0]
            vulnerable_libraries[library] = version

            # Check if the version is in the known vulnerabilities list
            for vuln in known_vulnerabilities.get(library, []):
                if version == vuln['version']:
                    vulnerable_libraries[library] = f"{version} (Potentially vulnerable: {vuln['vulnerability']})"

    return vulnerable_libraries

def detect_cloud_infrastructure(ip: str, cname_records: List[str]) -> Dict[str, str]:
    """Detect cloud infrastructure based on IP and CNAME records."""
    cloud_providers = {
        "Amazon Web Services": [
            r"\.amazonaws\.com$",
            r"\.aws\.amazon\.com$",
            r"^5[2-5]\.",  # AWS IP range
        ],
        "Microsoft Azure": [
            r"\.azure\.com$",
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.net$",
        ],
        "Google Cloud Platform": [
            r"\.googleusercontent\.com$",
            r"\.googleplex\.com$",
            r"^35\.",  # GCP IP range
        ],
        "Cloudflare": [
            r"\.cloudflare\.net$",
            r"\.cloudflare\.com$",
        ],
        "DigitalOcean": [
            r"\.digitalocean\.com$",
            r"\.digitaloceanspaces\.com$",
        ],
        "Heroku": [
            r"\.herokuapp\.com$",
            r"\.herokussl\.com$",
        ],
    }

    for provider, patterns in cloud_providers.items():
        for pattern in patterns:
            if any(re.search(pattern, cname) for cname in cname_records) or re.search(pattern, ip):
                return {"provider": provider}

    return {"provider": "Unknown"}

def detect_waf(headers: Dict[str, str], server: str) -> Dict[str, str]:
    """Detect Web Application Firewall based on HTTP headers and server information."""
    waf_signatures = {
        "Cloudflare": [
            ("server", "cloudflare"),
            ("cf-ray", r".*"),
        ],
        "AWS WAF": [
            ("x-amzn-trace-id", r".*"),
        ],
        "Imperva Incapsula": [
            ("x-iinfo", r".*"),
            ("x-cdn", "Incapsula"),
        ],
        "Akamai": [
            ("x-akamai-transformed", r".*"),
            ("akamai-origin-hop", r".*"),
        ],
        "F5 BIG-IP ASM": [
            ("x-web-security", "ASM"),
            ("x-web-protection", "ASM"),
        ],
        "Sucuri": [
            ("x-sucuri-id", r".*"),
            ("x-sucuri-cache", r".*"),
        ],
        "Barracuda": [
            ("x-barracuda-id", r".*"),
        ],
    }

    detected_waf = {"name": "None detected"}

    for waf_name, signatures in waf_signatures.items():
        for header, pattern in signatures:
            if header in headers and re.match(pattern, headers[header], re.IGNORECASE):
                detected_waf = {"name": waf_name}
                break
        if detected_waf["name"] != "None detected":
            break

    # Check server header as fallback
    if detected_waf["name"] == "None detected" and server:
        for waf_name, signatures in waf_signatures.items():
            if any(sig[0] == "server" and re.match(sig[1], server, re.IGNORECASE) for sig in signatures):
                detected_waf = {"name": waf_name}
                break

    return detected_waf

def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Analyze HTTP security headers."""
    security_headers = {
        "Strict-Transport-Security": {
            "description": "Ensures the browser always uses HTTPS for the domain",
            "recommendation": "max-age=31536000; includeSubDomains; preload"
        },
        "Content-Security-Policy": {
            "description": "Helps prevent XSS attacks",
            "recommendation": "Implement a policy suitable for your application"
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking attacks",
            "recommendation": "DENY or SAMEORIGIN"
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME type sniffing",
            "recommendation": "nosniff"
        },
        "Referrer-Policy": {
            "description": "Controls how much referrer information should be included with requests",
            "recommendation": "strict-origin-when-cross-origin"
        },
        "Permissions-Policy": {
            "description": "Controls which browser features and APIs can be used in the document",
            "recommendation": "Implement a policy suitable for your application"
        },
        "X-XSS-Protection": {
            "description": "Enables browser's built-in XSS protection (legacy)",
            "recommendation": "1; mode=block"
        }
    }

    analysis = {}
    for header, info in security_headers.items():
        if header.lower() in headers:
            analysis[header] = {
                "status": "Implemented",
                "value": headers[header.lower()],
                "description": info["description"]
            }
        else:
            analysis[header] = {
                "status": "Missing",
                "recommendation": info["recommendation"],
                "description": info["description"]
            }

    return analysis

def get_ssl_info(domain: str) -> Dict[str, any]:
    """Get SSL/TLS information for the domain using SSL Labs API."""
    base_url = "https://api.ssllabs.com/api/v3/analyze"
    
    # Start the analysis
    payload = {
        'host': domain,
        'startNew': 'off',  # Don't start a new scan, only retrieve cached results
        'fromCache': 'on',
        'all': 'done',
        'ignoreMismatch': 'on'
    }
    
    try:
        response = requests.get(base_url, params=payload, timeout=10)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        data = response.json()
        
        # Check if we have valid data
        if 'status' not in data:
            return {"error": "Unexpected API response format"}
        
        # Check if we have cached results
        if data['status'] not in ['READY', 'ERROR']:
            return {"error": "No cached results available"}
        
        if 'endpoints' not in data or not data['endpoints']:
            return {"error": "No endpoint information available"}
        
        endpoint = data['endpoints'][0]  # We'll just use the first endpoint
        
        return {
            "grade": endpoint.get('grade', 'Unknown'),
            "has_warnings": endpoint.get('hasWarnings', False),
            "is_exceptional": endpoint.get('isExceptional', False),
            "protocol_support": ", ".join(data.get('protocols', [])),
            "cert_expiry": data.get('certExpiry', 'Unknown'),
            "vulnerability_details": {
                "poodle": endpoint.get('details', {}).get('poodle', False),
                "heartbleed": endpoint.get('details', {}).get('heartbleed', False),
                "freak": endpoint.get('details', {}).get('freak', False),
                "logjam": endpoint.get('details', {}).get('logjam', False),
                "drownVulnerable": endpoint.get('details', {}).get('drownVulnerable', False)
            }
        }
    except requests.RequestException as e:
        return {"error": f"Failed to retrieve SSL information: {str(e)}"}

def check_data_breaches(domain: str) -> Dict[str, any]:
    """Check if the domain has appeared in known data breaches using HIBP's domain search."""
    url = f"https://haveibeenpwned.com/api/v3/breaches"
    headers = {
        "User-Agent": "PhantomProbe-OSINT-Tool"
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            all_breaches = response.json()
            domain_breaches = [
                breach for breach in all_breaches
                if domain.lower() in (breach.get('Domain', '').lower(), *breach.get('DomainNames', []))
            ]
            
            return {
                "total_breaches": len(domain_breaches),
                "breaches": [
                    {
                        "name": breach['Name'],
                        "date": breach['BreachDate'],
                        "description": breach['Description']
                    }
                    for breach in domain_breaches
                ]
            }
        else:
            return {"error": f"API request failed with status code {response.status_code}"}
    except RequestException as e:
        return {"error": f"Failed to check data breaches: {str(e)}"}

def check_http_response(url: str) -> Dict[str, any]:
    """Check HTTP response, analyze headers, fingerprint web application, and perform security header analysis."""
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        interesting_headers = analyze_headers(response.headers)
        fingerprints = fingerprint_web_application(response.headers, response.text)
        discovered_content = passive_content_discovery(url, response.text, response.headers)
        security_headers = analyze_security_headers(response.headers)
        vulnerable_libs = check_vulnerable_js_libraries(response.text)
        return {
            "status_code": str(response.status_code),
            "url": response.url,
            "interesting_headers": interesting_headers,
            "web_fingerprints": fingerprints,
            "discovered_content": list(discovered_content),
            "security_headers": security_headers,
            "vulnerable_js_libraries": vulnerable_libs
        }
    except RequestException:
        return {
            "status_code": "Error",
            "url": url,
            "interesting_headers": {},
            "web_fingerprints": {},
            "discovered_content": [],
            "security_headers": {},
            "vulnerable_js_libraries": {}
        }

def resolve_and_analyze_subdomain(subdomain: str, parent_domain: str) -> Dict[str, any]:
    """Resolve IP address and gather information for a given subdomain."""
    try:
        ip = socket.gethostbyname(subdomain)
        http_response = check_http_response(f"http://{subdomain}")
        https_response = check_http_response(f"https://{subdomain}")
        dns_records = get_dns_records(subdomain)
        shodan_info = check_shodan(ip)
        ssl_info = get_ssl_info(subdomain)
        
        # Combine fingerprints, discovered content, and security headers from both HTTP and HTTPS
        all_fingerprints = {
            **http_response.get('web_fingerprints', {}),
            **https_response.get('web_fingerprints', {})
        }
        all_discovered_content = list(set(
            http_response.get('discovered_content', []) +
            https_response.get('discovered_content', [])
        ))
        all_security_headers = {
            "http": http_response.get('security_headers', {}),
            "https": https_response.get('security_headers', {})
        }
        all_vulnerable_libs = {
            **http_response.get('vulnerable_js_libraries', {}),
            **https_response.get('vulnerable_js_libraries', {})
        }
        
        email_security = analyze_email_security(subdomain, dns_records)
        
        # Detect cloud infrastructure
        cname_records = dns_records.get('CNAME', [])
        cloud_info = detect_cloud_infrastructure(ip, cname_records)
        
        # Detect WAF
        headers = {**http_response.get('interesting_headers', {}), **https_response.get('interesting_headers', {})}
        server = headers.get('server', '')
        waf_info = detect_waf(headers, server)
        
        # Check for data breaches only for the main domain
        breach_info = check_data_breaches(parent_domain) if subdomain == parent_domain else {}
        
        return {
            "subdomain": subdomain,
            "ip": ip,
            "http_response": http_response,
            "https_response": https_response,
            "dns_records": dns_records,
            "email_security": email_security,
            "shodan_info": shodan_info,
            "ssl_info": ssl_info,
            "web_fingerprints": all_fingerprints,
            "discovered_content": all_discovered_content,
            "cloud_infrastructure": cloud_info,
            "web_application_firewall": waf_info,
            "data_breaches": breach_info,
            "security_headers": all_security_headers,
            "vulnerable_js_libraries": all_vulnerable_libs
        }
    except socket.gaierror:
        return {
            "subdomain": subdomain,
            "ip": "Unresolved",
            "http_response": {"status_code": "N/A", "url": "N/A", "interesting_headers": {}},
            "https_response": {"status_code": "N/A", "url": "N/A", "interesting_headers": {}},
            "dns_records": {},
            "email_security": {},
            "shodan_info": {},
            "ssl_info": {},
            "web_fingerprints": {},
            "discovered_content": [],
            "cloud_infrastructure": {"provider": "Unknown"},
            "web_application_firewall": {"name": "None detected"},
            "data_breaches": {},
            "security_headers": {"http": {}, "https": {}},
            "vulnerable_js_libraries": {}
        }

def process_subdomains(domain: str, subdomains: Set[str]) -> List[Dict[str, any]]:
    """Process all subdomains: resolve IP and gather information."""
    def safe_resolve_and_analyze(subdomain):
        try:
            return resolve_and_analyze_subdomain(subdomain, domain)
        except Exception as e:
            print(f"Error processing subdomain {subdomain}: {str(e)}")
            return {
                "subdomain": subdomain,
                "error": str(e)
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(safe_resolve_and_analyze, subdomains))
    return results

def generate_report(domain: str, subdomain_data: List[Dict[str, any]]) -> str:
    """Generate a comprehensive report of subdomain analysis."""
    whois_info = get_whois_info(domain)
    github_repos = search_github(domain)
    
    report = {
        "target_domain": domain,
        "whois_info": whois_info,
        "github_repositories": github_repos,
        "total_subdomains": len(subdomain_data),
        "subdomains": subdomain_data
    }
    
    report_filename = f"{domain}_passive_recon_report.json"
    with open(report_filename, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"Comprehensive passive reconnaissance report generated: {report_filename}")
    
    # Display a summary in the console
    print(f"\nPassive Reconnaissance Summary for {domain}:")
    print(f"Total subdomains discovered: {len(subdomain_data)}")
    print(f"WHOIS Registrar: {whois_info.get('registrar', 'Unknown')}")
    print(f"Creation Date: {whois_info.get('creation_date', 'Unknown')}")
    print(f"Expiration Date: {whois_info.get('expiration_date', 'Unknown')}")
    print(f"Associated GitHub Repositories: {len(github_repos)}")
    
    print("\nEmail Security Summary:")
    main_domain_data = next((sd for sd in subdomain_data if sd['subdomain'] == domain), None)
    if main_domain_data:
        email_security = main_domain_data.get('email_security', {})
        print(f"  MX Records: {', '.join(email_security.get('mx_records', ['None found']))}")
        print(f"  SPF Record: {'Exists' if email_security.get('spf', {}).get('exists', False) else 'Not found'}")
        print(f"  DMARC Record: {'Exists' if email_security.get('dmarc', {}).get('exists', False) else 'Not found'}")
    
    print("\nWeb Application Fingerprinting Summary:")
    for subdomain in subdomain_data:
        fingerprints = subdomain.get('web_fingerprints', {})
        if fingerprints:
            print(f"  {subdomain['subdomain']}:")
            for tech, version in fingerprints.items():
                print(f"    {tech}: {version}")
    
    print("\nCloud Infrastructure and WAF Detection:")
    for subdomain in subdomain_data:
        print(f"  {subdomain['subdomain']}:")
        print(f"    Cloud Provider: {subdomain['cloud_infrastructure']['provider']}")
        print(f"    WAF Detected: {subdomain['web_application_firewall']['name']}")
    
    print("\nHTTP Security Header Analysis:")
    for subdomain in subdomain_data:
        print(f"  {subdomain['subdomain']}:")
        for protocol in ['http', 'https']:
            print(f"    {protocol.upper()}:")
            security_headers = subdomain['security_headers'].get(protocol, {})
            if security_headers:
                for header, info in security_headers.items():
                    status = info['status']
                    if status == "Implemented":
                        print(f"      {header}: {status} - {info['value']}")
                    else:
                        print(f"      {header}: {status} - Recommendation: {info['recommendation']}")
            else:
                print(f"      No {protocol.upper()} security headers found or connection failed")
    
    print("\nVulnerable JavaScript Libraries:")
    for subdomain in subdomain_data:
        vuln_libs = subdomain.get('vulnerable_js_libraries', {})
        if vuln_libs:
            print(f"  {subdomain['subdomain']}:")
            for lib, version_info in vuln_libs.items():
                print(f"    {lib}: {version_info}")
    
    print("\nData Breach Information:")
    if main_domain_data and 'data_breaches' in main_domain_data:
        breach_info = main_domain_data['data_breaches']
        if 'error' in breach_info:
            print(f"  Error checking data breaches: {breach_info['error']}")
        else:
            print(f"  Total breaches found: {breach_info.get('total_breaches', 0)}")
            for breach in breach_info.get('breaches', [])[:5]:  # Limit to first 5 for brevity
                print(f"    - {breach['name']} ({breach['date']}):")
                print(f"      Description: {breach['description'][:100]}...")  # Truncate for brevity
            if len(breach_info.get('breaches', [])) > 5:
                print(f"      ... and {len(breach_info['breaches']) - 5} more")
    else:
        print("  No data breach information available")
    
    print("\nPassive Content Discovery Summary:")
    for subdomain in subdomain_data:
        discovered_content = subdomain.get('discovered_content', [])
        if discovered_content:
            print(f"  {subdomain['subdomain']}:")
            print(f"    Discovered {len(discovered_content)} potential resources")
            # Print first 5 discovered resources as an example
            for resource in discovered_content[:5]:
                print(f"      {resource}")
            if len(discovered_content) > 5:
                print(f"      ... and {len(discovered_content) - 5} more")
    
    print("\nFull details are available in the JSON report.")
    return report_filename

def main():
    parser = argparse.ArgumentParser(description="PhantomProbe: Advanced Passive Reconnaissance Tool")
    parser.add_argument("--visualize", action="store_true", help="Generate a visual report")
    args = parser.parse_args()

    display_banner()
    load_api_keys()
    domain = input("Enter the target domain: ")
    print(f"\nStarting passive reconnaissance for {domain}...")
    subdomains = enumerate_subdomains(domain)
    print(f"Found {len(subdomains)} unique subdomains. Gathering additional information...")
    subdomain_data = process_subdomains(domain, subdomains)
    report_file = generate_report(domain, subdomain_data)

    if args.visualize:
        print("Generating visual report...")
        with open(report_file, 'r') as f:
            report_data = json.load(f)
        create_visual_report(report_data)

if __name__ == "__main__":
    main()
