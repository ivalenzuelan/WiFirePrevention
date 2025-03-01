#!/usr/bin/env python3
"""
Advanced WiFi Device Movement Tracking
Uses multiple WiFi access points to triangulate device positions based on signal strength.
Requires running this script on multiple devices/access points and a central server.
"""

import argparse
import time
import json
import requests
import socket
import threading
import sys
import os
from datetime import datetime
from scapy.all import sniff, Dot11, RadioTap

# Configuration
NODE_ID = socket.gethostname()  # Use hostname as the node ID
SERVER_URL = "http://127.0.0.1:5000"  # Central server URL
INTERFACE = "wlan0"  # WiFi interface to monitor (change as needed)
LOG_FILE = f"signal_data_{NODE_ID}.json"

# Global variables
devices_data = {}
last_upload_time = 0
is_monitoring = False

def start_monitoring(interface):
    """
    Start monitoring WiFi signals using the given interface.
    
    Args:
        interface: WiFi interface to monitor
    """
    global is_monitoring
    
    print(f"[*] Starting monitoring on interface {interface}")
    is_monitoring = True
    
    try:
        # Start packet sniffing
        sniff(iface=interface, prn=process_packet, store=0)
    except Exception as e:
        print(f"[!] Error monitoring interface: {e}")
        is_monitoring = False

def process_packet(packet):
    """
    Process a captured WiFi packet.
    
    Args:
        packet: Captured packet
    """
    global devices_data
    
    # Check if we're still supposed to be monitoring
    if not is_monitoring:
        return
    
    # Check if packet has WiFi and signal strength information
    if packet.haslayer(Dot11) and packet.haslayer(RadioTap):
        # Get MAC address
        if packet.haslayer(Dot11):
            mac = packet.addr2
            if mac is None:
                return
            
            # Ignore broadcast, multicast, and locally administered MACs
            if mac.startswith(('01', '03', '05', '07', '09', '0b', '0d', '0f', 'ff')):
                return
            
            # Get signal strength (RSSI)
            try:
                signal_strength = packet[RadioTap].dBm_AntSignal
            except:
                # Some packets don't have the signal strength field
                return
            
            # Store the data
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if mac not in devices_data:
                devices_data[mac] = {
                    'mac': mac,
                    'first_seen': timestamp,
                    'signals': []
                }
            
            # Add signal data
            devices_data[mac]['last_seen'] = timestamp
            devices_data[mac]['signals'].append({
                'timestamp': timestamp,
                'rssi': signal_strength,
                'node_id': NODE_ID
            })
            
            # Keep only the last 10 signal measurements per device
            if len(devices_data[mac]['signals']) > 10:
                devices_data[mac]['signals'] = devices_data[mac]['signals'][-10:]

def upload_data_periodically(interval=60):
    """
    Upload the collected data to the central server periodically.
    
    Args:
        interval: Upload interval in seconds
    """
    global last_upload_time
    
    while is_monitoring:
        current_time = time.time()
        
        # Check if it's time to upload
        if current_time - last_upload_time >= interval:
            upload_data()
            last_upload_time = current_time
        
        # Sleep for a short time to avoid consuming too much CPU
        time.sleep(1)

def upload_data():
    """Upload the collected data to the central server."""
    global devices_data
    
    if not devices_data:
        print("[*] No data to upload")
        return
    
    try:
        # Prepare the data
        upload_data = {
            'node_id': NODE_ID,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'devices': list(devices_data.values())
        }
        
        # Upload to server
        response = requests.post(
            f"{SERVER_URL}/api/node_data",
            json=upload_data,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            print(f"[+] Data uploaded successfully: {len(devices_data)} devices")
            
            # Save to local log file
            with open(LOG_FILE, 'w') as f:
                json.dump(upload_data, f, indent=2)
        else:
            print(f"[!] Failed to upload data: {response.status_code}")
    
    except Exception as e:
        print(f"[!] Error uploading data: {e}")

def main():
    parser = argparse.ArgumentParser(description='Advanced WiFi Device Movement Tracking')
    parser.add_argument('-i', '--interface', default=INTERFACE, help=f'WiFi interface to monitor (default: {INTERFACE})')
    parser.add_argument('-s', '--server', default=SERVER_URL, help=f'Central server URL (default: {SERVER_URL})')
    parser.add_argument('-u', '--upload-interval', type=int, default=60, help='Upload interval in seconds (default: 60)')
    
    args = parser.parse_args()
    
    global SERVER_URL, INTERFACE
    SERVER_URL = args.server
    INTERFACE = args.interface
    
    print(f"[*] Node ID: {NODE_ID}")
    print(f"[*] Server URL: {SERVER_URL}")
    print(f"[*] Interface: {INTERFACE}")
    print(f"[*] Upload interval: {args.upload_interval} seconds")
    
    # Start the upload thread
    upload_thread = threading.Thread(target=upload_data_periodically, args=(args.upload_interval,))
    upload_thread.daemon = True
    upload_thread.start()
    
    try:
        # Start monitoring
        start_monitoring(INTERFACE)
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user")
        is_monitoring = False
        upload_data()  # Upload any remaining data

if __name__ == "__main__":
    main()