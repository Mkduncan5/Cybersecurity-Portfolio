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

