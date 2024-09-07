import json
import sys
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import numpy as np

def load_json_report(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def create_visual_report(data):
    domain = data['target_domain']
    subdomains = data['subdomains']

    # Prepare data for visualization
    total_subdomains = len(subdomains)
    resolved_subdomains = sum(1 for s in subdomains if s['ip'] != 'Unresolved')
    https_enabled = sum(1 for s in subdomains if s['https_response']['status_code'] != 'Error')
    waf_protected = sum(1 for s in subdomains if s['web_application_firewall']['name'] != 'None detected')
    vulnerable_js = sum(1 for s in subdomains if s['vulnerable_js_libraries'])
    
    # Count occurrences of each cloud provider
    cloud_providers = {}
    for s in subdomains:
        provider = s['cloud_infrastructure']['provider']
        cloud_providers[provider] = cloud_providers.get(provider, 0) + 1

    # Create the main figure
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 18))
    fig.suptitle(f'Visual Report for {domain}', fontsize=16)

    # Subdomain statistics
    ax1.bar(['Total', 'Resolved', 'HTTPS Enabled', 'WAF Protected'], 
            [total_subdomains, resolved_subdomains, https_enabled, waf_protected])
    ax1.set_title('Subdomain Statistics')
    ax1.set_ylabel('Count')

    # Cloud provider distribution
    providers = list(cloud_providers.keys())
    counts = list(cloud_providers.values())
    ax2.pie(counts, labels=providers, autopct='%1.1f%%', startangle=90)
    ax2.set_title('Cloud Provider Distribution')

    # Security findings
    security_data = [
        ('Vulnerable JS', sum(1 for s in subdomains if s['vulnerable_js_libraries'])),
        ('Missing HTTPS', total_subdomains - https_enabled),
        ('Missing WAF', total_subdomains - waf_protected),
        ('Data Breaches', data['subdomains'][0]['data_breaches'].get('total_breaches', 0))
    ]
    security_labels, security_counts = zip(*security_data)
    y_pos = np.arange(len(security_labels))
    ax3.barh(y_pos, security_counts)
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels(security_labels)
    ax3.invert_yaxis()
    ax3.set_title('Security Findings')
    ax3.set_xlabel('Count')

    plt.tight_layout()
    plt.savefig(f'{domain}_visual_report.png')
    print(f"Visual report saved as {domain}_visual_report.png")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python visualize_report.py <path_to_json_report>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    data = load_json_report(json_file)
    create_visual_report(data)
