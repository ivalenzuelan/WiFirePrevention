#!/usr/bin/env python3
"""
Central Server for WiFi Device Tracking
Collects data from multiple tracking nodes and provides a unified dashboard.
Estimates device locations based on signal strength from different nodes.
"""

from flask import Flask, render_template, jsonify, request
import pandas as pd
import numpy as np
import json
import os
import time
from datetime import datetime, timedelta
import threading

app = Flask(__name__)

# Global variables
nodes_data = {}  # Data from tracking nodes
device_locations = {}  # Estimated locations of devices
floor_plan = {
    "width": 100,  # Width of the floor plan in meters
    "height": 80,  # Height of the floor plan in meters
    "nodes": {
        # Node positions (x, y) on the floor plan
        # Will be populated dynamically when nodes connect
    }
}

# Mutex for thread-safe access to data
data_lock = threading.Lock()

def calculate_device_locations():
    """
    Calculate estimated device locations based on signal strength from different nodes.
    Uses a simple weighted centroid algorithm.
    """
    global device_locations, nodes_data, floor_plan
    
    with data_lock:
        # Get all unique devices
        all_devices = set()
        for node_id, node_data in nodes_data.items():
            for device in node_data.get('devices', []):
                all_devices.add(device['mac'])
        
        # Calculate position for each device
        for mac in all_devices:
            signals = []
            
            # Collect signal data from all nodes
            for node_id, node_data in nodes_data.items():
                if node_id not in floor_plan['nodes']:
                    continue  # Skip nodes without known positions
                
                node_pos = floor_plan['nodes'][node_id]
                
                # Find this device in the node's data
                for device in node_data.get('devices', []):
                    if device['mac'] == mac and device.get('signals'):
                        # Get the most recent signal measurement
                        latest_signal = device['signals'][-1]
                        rssi = latest_signal['rssi']
                        
                        # Convert RSSI to approximate distance
                        # Using a simple model: distance = 10^((TxPower - RSSI)/(10 * n))
                        # Where TxPower is typically -59 dBm at 1 meter, and n is path loss exponent (typically 2