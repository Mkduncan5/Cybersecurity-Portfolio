#!/usr/bin/env python3
from scapy.all import *
from collections import Counter
import logging
import argparse
import sys
from datetime import datetime

class NetworkMonitor:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_counts = Counter()
        self.suspicious_ips = set()
        
        logging.basicConfig(
            filename=f"network_monitor_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )


    def detect_port_scan(self, ip, port):
        """Enhanced port scan detection"""
        # Track unique ports per IP
        if ip not in self.port_scan_tracking:
            self.port_scan_tracking[ip] = {
                ports: set(),
                last_scan: datetime.now(),
                scan_rate: 0
            }
        
        tracking = self.port_scan_tracking[ip]
        tracking["ports"].add(port)
        current_time = datetime.now()
        time_diff = (current_time - tracking["last_scan"]).total_seconds()
        
        if time_diff > 0:
            tracking["scan_rate"] = len(tracking["ports"]) / time_diff
        
        # Alert conditions
        if len(tracking["ports"]) > 10 or tracking["scan_rate"] > 2:
            if ip not in self.suspicious_ips:
                self.suspicious_ips.add(ip)
                logging.warning(f"Port scan detected - IP: {ip}, Unique Ports: {len(tracking[ports])}, Rate: {tracking[scan_rate]:.2f} ports/sec")


    def __init__(self, interface=None):
        self.interface = interface
        self.packet_counts = Counter()
        self.suspicious_ips = set()
        self.port_scan_tracking = {}  # Add this line

