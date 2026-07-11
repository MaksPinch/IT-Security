from scapy.all import IP, UDP, Raw, send

packet = (
    IP(dst="127.0.0.1")
    / UDP(sport=44444, dport=9999)
    / Raw(load="Test packet from Scapy")
)

send(packet)

print("Test packet sent to 127.0.0.1:9999")