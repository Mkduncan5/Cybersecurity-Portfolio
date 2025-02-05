#!/usr/bin/env python3
from scapy.all import *
from collections import Counter
import logging
import argparse
import sys
import time
from datetime import datetime
class NetworkMonitor:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_counts = Counter()
        self.suspicious_ips = set()
        self.port_scan_tracking = {}
        logging.basicConfig(
            filename=f"network_monitor_{datetime.now().strftime(\"%Y%m%d_%H%M%S\")}.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )
    def detect_port_scan(self, ip, port):
       if ip not in self.port_scan_tracking:
           self.port_scan_tracking[ip] = {
               "ports": set(),
               "last_scan": datetime.now(),
               "scan_rate": 0
           }
       tracking = self.port_scan_tracking[ip]
       tracking["ports"].add(port)
       current_time = datetime.now()
       time_diff = (current_time - tracking["last_scan"]).total_seconds()
       if time_diff > 0:
           tracking["scan_rate"] = len(tracking["ports"]) / time_diff
       if len(tracking["ports"]) > 10 or tracking["scan_rate"] > 2:
           if ip not in self.suspicious_ips:
               self.suspicious_ips.add(ip)
               logging.warning(f"Port scan detected - IP: {ip}")
    def apply_packet_filter(self, packet):
       if IP not in packet:
           return False
       if packet[IP].proto not in [6, 17]:
           return False
       return True
    def packet_callback(self, packet):
       if not self.apply_packet_filter(packet):
           return
       src_ip = packet[IP].src
       dst_ip = packet[IP].dst
       self.packet_counts[src_ip] += 1
       if TCP in packet:
           self.detect_port_scan(src_ip, packet[TCP].dport)
       logging.info(f"Packet: {src_ip} -> {dst_ip}")
    def track_statistics(self):
       stats = {
           "total_packets": sum(self.packet_counts.values()),
           "unique_ips": len(self.packet_counts),
           "suspicious_ips": len(self.suspicious_ips),
           "top_talkers": self.packet_counts.most_common(5)
       }
       logging.info(f"Statistics: {stats}")
       return stats
    def start_capture(self, packet_count=None):
       try:
           logging.info(f"Starting capture on {self.interface}")
           sniff(iface=self.interface, prn=self.packet_callback, count=packet_count)
       except Exception as e:
           logging.error(f"Capture error: {str(e)}")
           sys.exit(1)
def main():
   parser = argparse.ArgumentParser(description="Network Security Monitor")
   parser.add_argument("-i", "--interface", help="Network interface to monitor")
   parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
   args = parser.parse_args()
   monitor = NetworkMonitor(args.interface)
   monitor.start_capture(args.count)

if __name__ == "__main__":
   main()
    def handle_error(self, error_msg):
        logging.error(f"Error: {error_msg}")
        sys.exit(1)
    def alert(self, alert_type, details):
        """Send real-time alerts"""
        alert_msg = f"ALERT [{alert_type}]: {details}"
        print(alert_msg)
        logging.warning(alert_msg)
    def check_port_sequence(self, ip):
        """Detect sequential port scanning"""
        ports = sorted(list(self.port_scan_tracking[ip]["ports"]))
        sequences = 0
        for i in range(len(ports)-1):
            if ports[i+1] - ports[i] == 1:
                sequences += 1
        return sequences > 5
    def monitor_traffic_patterns(self):
        """Monitor traffic for anomalies"""
        for ip in self.packet_counts:
            if self.packet_counts[ip] > 1000:
                self.alert("High Traffic", f"IP {ip} sent {self.packet_counts[ip]} packets")
    def generate_report(self):
        """Generate security report"""
        report = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stats": self.track_statistics(),
            "threats": list(self.suspicious_ips)
        }
        return report
