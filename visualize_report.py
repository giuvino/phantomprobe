import json
import sys
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
import numpy as np
import networkx as nx


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
    if counts:  # Only create pie chart if there's data
        ax2.pie(counts, labels=providers, autopct='%1.1f%%', startangle=90)
        ax2.set_title('Cloud Provider Distribution')
    else:
        ax2.text(0.5, 0.5, 'No cloud provider data available', ha='center', va='center')
        ax2.axis('off')

    # Security findings
    security_data = [
        ('Vulnerable JS', sum(1 for s in subdomains if s['vulnerable_js_libraries'])),
        ('Missing HTTPS', total_subdomains - https_enabled),
        ('Missing WAF', total_subdomains - waf_protected),
        ('Data Breaches', data['subdomains'][0]['data_breaches'].get('total_breaches', 0) if data['subdomains'] else 0)
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
    create_subdomain_graph(domain, subdomains)

def create_subdomain_graph(domain, subdomains):
    G = nx.Graph()
    
    # Add main domain node
    G.add_node(domain, color='red', size=2000)
    
    for subdomain in subdomains:
        name = subdomain['subdomain']
        ip = subdomain['ip']
        waf = subdomain['web_application_firewall']['name']
        cloud = subdomain['cloud_infrastructure']['provider']
        
        # Add subdomain node
        G.add_node(name, color='blue', size=1000)
        G.add_edge(domain, name)
        
        # Add IP node if resolved
        if ip != 'Unresolved':
            G.add_node(ip, color='green', size=500)
            G.add_edge(name, ip)
        
        # Add WAF node if detected
        if waf != 'None detected':
            waf_node = f"WAF: {waf}"
            G.add_node(waf_node, color='yellow', size=300)
            G.add_edge(name, waf_node)
        
        # Add cloud provider node if detected
        if cloud != 'Unknown':
            cloud_node = f"Cloud: {cloud}"
            G.add_node(cloud_node, color='purple', size=300)
            G.add_edge(name, cloud_node)

    # Set up the plot
    plt.figure(figsize=(20, 20))
    pos = nx.spring_layout(G, k=0.5, iterations=50)
    
    # Draw nodes
    node_colors = [G.nodes[n]['color'] for n in G.nodes()]
    node_sizes = [G.nodes[n]['size'] for n in G.nodes()]
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.8)
    
    # Draw edges
    nx.draw_networkx_edges(G, pos, edge_color='gray', alpha=0.5)
    
    # Draw labels
    nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold")
    
    plt.title(f"Domain Structure for {domain}")
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(f'{domain}_domain_structure.png', dpi=300, bbox_inches='tight')
    print(f"Domain structure graph saved as {domain}_domain_structure.png")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python visualize_report.py <path_to_json_report>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    with open(json_file, 'r') as f:
        data = json.load(f)
    create_visual_report(data)

