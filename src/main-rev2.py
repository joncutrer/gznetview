import argparse
import nmap
import scapy.all as scapy
import plotly.graph_objects as go
from collections import defaultdict

def scan_network(network):
    nm = nmap.PortScanner()
    nm.scan(network, arguments='-sn')
    hosts = nm.all_hosts()
    return hosts

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    return answered_list[0][1].hwsrc if answered_list else 'Unknown'

def build_graph_data(hosts):
    nodes = []
    edges = defaultdict(list)
    
    for host in hosts:
        mac = get_mac(host)
        nodes.append(mac)
        
        # For this example, we'll consider all hosts are connected to each other.
        # You can adjust this part based on your actual network topology.
        for node in nodes:
            if node != mac:
                edges[node].append(mac)
    
    return nodes, edges


def plot_network(nodes, edges):
    x_values = []
    y_values = []

    for node, connected_nodes in edges.items():
        for connected_node in connected_nodes:
            x_values.extend([nodes.index(node), nodes.index(connected_node), None])
            y_values.extend([nodes.index(connected_node), nodes.index(node), None])

    edge_trace = go.Scatter(
        x=x_values,
        y=y_values,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    node_trace = go.Scatter(
        x=[nodes.index(node) for node in nodes],
        y=[nodes.index(node) for node in nodes],
        mode='markers',
        hoverinfo='text',
        marker=dict(
            showscale=True,
            colorscale='YlGnBu',
            reversescale=True,
            color=[],
            size=10,
            colorbar=dict(
                thickness=15,
                title='Node Connections',
                xanchor='left',
                titleside='right'
            ),
            line=dict(width=2)))

    fig = go.Figure(data=[edge_trace, node_trace],
                 layout=go.Layout(
                    title='<br>Network graph',
                    titlefont=dict(size=16),
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20,l=5,r=5,t=40),
                    annotations=[ dict(
                        showarrow=False,
                        xref="paper", yref="paper",
                        x=0.005, y=-0.002 ) ],
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)))

    fig.show()

def main():
    parser = argparse.ArgumentParser(description="Network Scanner and Graph Plotter")
    parser.add_argument('network', type=str, help='The network to scan in CIDR notation (e.g., 192.168.1.0/24)')
    args = parser.parse_args()

    hosts = scan_network(args.network)
    nodes, edges = build_graph_data(hosts)
    plot_network(nodes, edges)

if __name__ == "__main__":
    main()
