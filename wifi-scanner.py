#!/usr/bin/env python3
"""
WiFi Device Scanner - Basic Prototype
Scans the local network for connected devices using ARP requests.
"""

import argparse
import time
from datetime import datetime
from scapy.all import ARP, Ether, srp
import pandas as pd
import csv
import os

def scan_network(ip_range):
    """
    Scan the network using ARP requests.
    
    Args:
        ip_range: IP range to scan (e.g., "192.168.1.0/24")
        
    Returns:
        List of dictionaries containing MAC and IP addresses of discovered devices
    """
    # Create ARP packet
    arp = ARP(pdst=ip_range)
    # Create Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Stack them
    packet = ether/arp

    print(f"[*] Scanning {ip_range}...")
    start_time = time.time()
    
    # Send packets and capture responses
    result = srp(packet, timeout=3, verbose=0)[0]
    
    # Process responses
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    scan_time = time.time() - start_time
    print(f"[+] Scan completed in {scan_time:.2f} seconds")
    print(f"[+] {len(devices)} devices found")
    
    return devices

def display_results(devices):
    """
    Display the scan results in a table format.
    
    Args:
        devices: List of dictionaries containing device information
    """
    print("\nMAC Address\t\tIP Address")
    print("-" * 45)
    for device in devices:
        print(f"{device['mac']}\t{device['ip']}")
    print("")

def log_results(devices, filename="device_log.csv"):
    """
    Log scan results to a CSV file with timestamp.
    
    Args:
        devices: List of dictionaries containing device information
        filename: CSV file to save results
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Check if file exists to determine if we need to write headers
    file_exists = os.path.isfile(filename)
    
    with open(filename, 'a', newline='') as file:
        fieldnames = ['timestamp', 'ip', 'mac']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        
        if not file_exists:
            writer.writeheader()
        
        for device in devices:
            device['timestamp'] = timestamp
            writer.writerow(device)
    
    print(f"[+] Results logged to {filename}")

def calculate_statistics(filename="device_log.csv"):
    """
    Calculate basic statistics from logged data.
    
    Args:
        filename: CSV file containing scan logs
    """
    if not os.path.isfile(filename):
        print("[!] No log file found to calculate statistics")
        return
    
    try:
        df = pd.read_csv(filename)
        # Count unique devices
        unique_devices = df['mac'].nunique()
        # Get latest scan
        latest_scan = df['timestamp'].max()
        # Count devices in latest scan
        latest_count = df[df['timestamp'] == latest_scan]['mac'].count()
        
        print("\nDevice Statistics:")
        print(f"Total unique devices seen: {unique_devices}")
        print(f"Devices in latest scan: {latest_count}")
        print(f"Latest scan time: {latest_scan}")
        
    except Exception as e:
        print(f"[!] Error calculating statistics: {e}")

def main():
    parser = argparse.ArgumentParser(description='Scan for devices on the local network')
    parser.add_argument('-r', '--range', default='192.168.1.0/24', help='IP range to scan (default: 192.168.1.0/24)')
    parser.add_argument('-l', '--log', action='store_true', help='Log results to CSV')
    parser.add_argument('-s', '--stats', action='store_true', help='Calculate statistics from log file')
    parser.add_argument('-c', '--continuous', type=int, help='Run continuous scans with specified interval (seconds)')
    
    args = parser.parse_args()
    
    if args.stats:
        calculate_statistics()
        return
    
    if args.continuous:
        print(f"[*] Running continuous scans every {args.continuous} seconds. Press Ctrl+C to stop.")
        try:
            while True:
                devices = scan_network(args.range)
                display_results(devices)
                if args.log:
                    log_results(devices)
                time.sleep(args.continuous)
        except KeyboardInterrupt:
            print("\n[*] Scan stopped by user")
    else:
        devices = scan_network(args.range)
        display_results(devices)
        if args.log:
            log_results(devices)

if __name__ == "__main__":
    main()