from scapy.all import wrpcap, IP, TCP
# Create a fake packet simulating an attack on port 3389 (RDP)
fake_packet = IP(src="10.0.0.99", dst="192.168.1.5")/TCP(dport=3389)
wrpcap("test_attack.pcap", [fake_packet])
print("test_attack.pcap created!")