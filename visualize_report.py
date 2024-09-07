import json
import sys
import matplotlib.pyplot as plt
import numpy as np
import networkx as nx
from qbstyles import mpl_style
from matplotlib.colors import to_rgba
from matplotlib.patheffects import withStroke

# Apply the light style
mpl_style(dark=False)

def create_visual_report(data):
    domain = data['target_domain']
    subdomains = data['subdomains']

    # Prepare data for visualization
    total_subdomains = len(subdomains)
    resolved_subdomains = sum(1 for s in subdomains if s['ip'] != 'Unresolved')
    https_enabled = sum(1 for s in subdomains if s['https_response']['status_code'] != 'Error')
    waf_protected = sum(1 for s in subdomains if s['web_application_firewall']['name'] != 'None detected')
    
    cloud_providers = {}
    for s in subdomains:
        provider = s['cloud_infrastructure']['provider']
        cloud_providers[provider] = cloud_providers.get(provider, 0) + 1

    if cloud_providers:
        create_cloud_distribution(domain, cloud_providers)
    else:
        print("No cloud provider data available. Skipping cloud distribution graph.")

    # Create separate figures for each graph
    create_subdomain_statistics(domain, total_subdomains, resolved_subdomains, https_enabled, waf_protected)
    create_cloud_distribution(domain, cloud_providers)
    create_security_findings(domain, subdomains, total_subdomains, https_enabled, waf_protected)

    # Create node graph
    create_subdomain_graph(domain, subdomains)

def create_subdomain_statistics(domain, total, resolved, https, waf):
    plt.figure(figsize=(12, 8))
    bar_color = '#ff6b6b'  # A softer red that works well on light backgrounds
    text_color = '#333333'  # Dark gray for text, providing good contrast on light background
    
    bars = plt.bar(['Total', 'Resolved', 'HTTPS Enabled', 'WAF Protected'], 
            [total, resolved, https, waf],
            color=bar_color)
    
    plt.title(f'Subdomain Statistics for {domain}', fontsize=20, color=text_color)
    plt.ylabel('Count', fontsize=16, color=text_color)
    plt.tick_params(axis='both', which='major', labelsize=14, colors=text_color)
    
    # Adding value labels on top of each bar
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height}',
                 ha='center', va='bottom', fontsize=14, color=text_color)
    
    # Removing top and right spines for a cleaner look
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(f'{domain}_subdomain_statistics.png', dpi=300, bbox_inches='tight', facecolor='white', edgecolor='none')
    print(f"Subdomain statistics saved as {domain}_subdomain_statistics.png")


def create_cloud_distribution(domain, cloud_providers):
    plt.figure(figsize=(12, 8), facecolor='white')
    providers = list(cloud_providers.keys())
    counts = list(cloud_providers.values())
    
    if counts:
        # Use a color palette that works well for both single and multiple providers
        colors = plt.cm.Set3(np.linspace(0, 1, max(len(providers), 3)))
        
        # Create pie chart without labels
        plt_output = plt.pie(counts, colors=colors, autopct='', startangle=90)
        wedges = plt_output[0]  # The wedges are always the first element
        
        # Add a legend
        legend_labels = [f'{provider} ({count})' for provider, count in zip(providers, counts)]
        plt.legend(wedges, legend_labels, title="Cloud Providers", 
                   loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
        
        plt.title(f'Cloud Provider Distribution for {domain}', fontsize=20, color='black')
    else:
        plt.text(0.5, 0.5, 'No cloud provider data available', 
                 ha='center', va='center', fontsize=16, color='black')
        plt.axis('off')
    
    plt.tight_layout()
    plt.savefig(f'{domain}_cloud_distribution.png', dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    print(f"Cloud distribution saved as {domain}_cloud_distribution.png")

def create_security_findings(domain, subdomains, total_subdomains, https_enabled, waf_protected):
    plt.figure(figsize=(12, 8))
    bar_color = '#4ecdc4'  # A teal color that works well on light backgrounds
    text_color = '#333333'  # Dark gray for text

    security_data = [
        ('Vulnerable JS', sum(1 for s in subdomains if s['vulnerable_js_libraries'])),
        ('Missing HTTPS', total_subdomains - https_enabled),
        ('Missing WAF', total_subdomains - waf_protected),
        ('Data Breaches', subdomains[0]['data_breaches'].get('total_breaches', 0) if subdomains else 0)
    ]
    security_labels, security_counts = zip(*security_data)
    y_pos = np.arange(len(security_labels))
    
    bars = plt.barh(y_pos, security_counts, color=bar_color)
    plt.yticks(y_pos, security_labels, fontsize=14, color=text_color)
    plt.gca().invert_yaxis()
    plt.title(f'Security Findings for {domain}', fontsize=20, color=text_color)
    plt.xlabel('Count', fontsize=16, color=text_color)
    plt.tick_params(axis='both', which='major', labelsize=14, colors=text_color)
    
    # Adding value labels at the end of each bar
    for bar in bars:
        width = bar.get_width()
        plt.text(width, bar.get_y() + bar.get_height()/2.,
                 f'{width}',
                 ha='left', va='center', fontsize=14, color=text_color)
    
    # Removing top and right spines
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(f'{domain}_security_findings.png', dpi=300, bbox_inches='tight', facecolor='white', edgecolor='none')
    print(f"Security findings saved as {domain}_security_findings.png")

def create_subdomain_graph(domain, subdomains):
    G = nx.Graph()
    
    colors = {
        'main': '#ff6b6b',  # Soft red for the main domain
        'subdomain': '#4ecdc4',  # Teal for subdomains
        'ip': '#45b7d1',  # Light blue for IP addresses
        'waf': '#feca57',  # Yellow for WAF
        'cloud': '#a55eea'  # Purple for cloud providers
    }
    
    G.add_node(domain, color=colors['main'], size=3000)
    
    for subdomain in subdomains:
        name = subdomain['subdomain']
        ip = subdomain['ip']
        waf = subdomain['web_application_firewall']['name']
        cloud = subdomain['cloud_infrastructure']['provider']
        
        G.add_node(name, color=colors['subdomain'], size=1500)
        G.add_edge(domain, name)
        
        if ip != 'Unresolved':
            G.add_node(ip, color=colors['ip'], size=1000)
            G.add_edge(name, ip)
        
        if waf != 'None detected':
            waf_node = f"WAF: {waf}"
            G.add_node(waf_node, color=colors['waf'], size=800)
            G.add_edge(name, waf_node)
        
        if cloud != 'Unknown':
            cloud_node = f"Cloud: {cloud}"
            G.add_node(cloud_node, color=colors['cloud'], size=800)
            G.add_edge(name, cloud_node)

    plt.figure(figsize=(24, 24), facecolor='white')
    pos = nx.spring_layout(G, k=0.9, iterations=50)
    
    node_colors = [G.nodes[n]['color'] for n in G.nodes()]
    node_sizes = [G.nodes[n]['size'] for n in G.nodes()]
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes)
    
    # Increase edge visibility for light mode
    nx.draw_networkx_edges(G, pos, edge_color='#666666', alpha=0.6, width=1.0)
    
    labels = nx.draw_networkx_labels(G, pos, font_size=10, font_weight="bold", font_color='black')
    for node, text in labels.items():
        text.set_path_effects([withStroke(linewidth=2, foreground='white')])
    
    plt.title(f"Domain Structure for {domain}", fontsize=24, color='black')
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(f'{domain}_domain_structure.png', dpi=300, bbox_inches='tight', facecolor='white', edgecolor='none')
    print(f"Domain structure graph saved as {domain}_domain_structure.png")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python visualize_report.py <path_to_json_report>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    with open(json_file, 'r') as f:
        data = json.load(f)
    create_visual_report(data)
