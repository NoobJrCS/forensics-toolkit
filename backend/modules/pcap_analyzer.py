from scapy.all import rdpcap, IP, TCP

def analyze_pcap(filepath):
    suspicious_ips = set()
    alerts = []
    
    try:
        # Read the packet capture file
        packets = rdpcap(filepath)
        
        for pkt in packets:
            # Check if the packet has an IP layer and a TCP layer
            if IP in pkt and TCP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                dst_port = pkt[TCP].dport
                
                # Flag traffic targeting common attack ports (SSH, RDP, Telnet)
                if dst_port in [22, 23, 3389]:
                    suspicious_ips.add(src_ip)
                    alerts.append(f"Alert: Traffic from {src_ip} to {dst_ip} on port {dst_port}")
                    
        return list(suspicious_ips), alerts
    except Exception as e:
        return [], [f"Error analyzing PCAP: {str(e)}"]