# PhantomProbe: Advanced Passive Reconnaissance Tool

PhantomProbe is a comprehensive passive reconnaissance and information gathering tool designed for cybersecurity professionals, penetration testers, and ethical hackers. It performs in-depth analysis of target domains without actively interacting with their systems, ensuring stealthy and non-intrusive intelligence collection.

<img width="752" alt="image" src="https://github.com/user-attachments/assets/2e2a49a0-ed7b-427d-b8bd-d352788265af">

## Key Features

- Subdomain enumeration
- DNS record analysis
- Web technology fingerprinting
- Passive content discovery
- SSL/TLS configuration analysis
- Email security assessment (SPF, DMARC)
- Cloud infrastructure detection
- Web Application Firewall (WAF) identification
- Vulnerability checks for JavaScript libraries
- Data breach information retrieval
- HTTP security header analysis
- WHOIS information gathering
- GitHub repository discovery

## Information Gathered

PhantomProbe collects a wide range of information, including but not limited to:

- Subdomains and their IP addresses
- DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Web server and technology stack details
- Potential vulnerable paths and resources
- SSL/TLS grades and vulnerabilities
- Email security configurations
- Cloud service providers in use
- Presence and type of WAF
- Potentially vulnerable JavaScript libraries
- Historical data breaches
- Security header configurations
- Domain registration and expiration details
- Associated public GitHub repositories

## Dependencies

PhantomProbe requires the following Python libraries:

- dnspython
- python-whois
- PyGithub
- shodan
- requests

Install these dependencies using pip:
`pip install dnspython python-whois PyGithub shodan requests`

## API Keys Required

To utilize all features, you'll need to obtain and configure API keys for:

- Shodan
- GitHub

Set these as environment variables before running the script:
`export SHODAN_API_KEY="your_shodan_api_key"`
`export GITHUB_API_KEY="your_github_api_key"`

## Usage

Run the script from the command line:
`python phantom-probe.py`

Enter the target domain when prompted. PhantomProbe will then conduct its analysis and generate a comprehensive report in JSON format, along with a summary in the console output.

## Note

PhantomProbe is designed for ethical use only. Ensure you have proper authorization before performing reconnaissance on any domain or system you do not own or have explicit permission to test.

