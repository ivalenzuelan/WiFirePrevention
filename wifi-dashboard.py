#!/usr/bin/env python3
"""
WiFi Device Tracking Dashboard
A simple Flask web application to display connected devices and their movement.
"""

from flask import Flask, render_template, jsonify
from scapy.all import ARP, Ether, srp
import pandas as pd
import time
import threading
import os
from datetime import datetime
import json

app = Flask(__name__)

# Global variables to store scan data
devices_data = []
device_history = {}
scan_timestamp = None
scanning_active = False

def scan_network(ip_range="192.168.1.0/24"):
    """
    Scan the network using ARP requests.
    
    Args:
        ip_range: IP range to scan (e.g., "192.168.1.0/24")
        
    Returns:
        List of dictionaries containing device information
    """
    global devices_data, scan_timestamp
    
    # Create ARP packet
    arp = ARP(pdst=ip_range)
    # Create Ethernet frame
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Stack them
    packet = ether/arp
    
    # Send packets and capture responses
    result = srp(packet, timeout=3, verbose=0)[0]
    
    # Process responses
    devices = []
    timestamp = datetime.now()
    scan_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    
    for sent, received in result:
        device = {
            'ip': received.psrc, 
            'mac': received.hwsrc,
            'last_seen': scan_timestamp,
            'status': 'active'
        }
        
        # Track device history
        if received.hwsrc in device_history:
            # Device was seen before
            history = device_history[received.hwsrc]
            
            # Check if IP changed
            if history['last_ip'] != received.psrc:
                device['status'] = 'moved'
                
            # Update history
            history['last_seen'] = timestamp
            history['last_ip'] = received.psrc
            history['seen_count'] += 1
            
        else:
            # New device
            device_history[received.hwsrc] = {
                'first_seen': timestamp,
                'last_seen': timestamp,
                'last_ip': received.psrc,
                'seen_count': 1
            }
            device['status'] = 'new'
        
        devices.append(device)
    
    # Check for missing devices (devices that were seen before but not in this scan)
    current_macs = {device['mac'] for device in devices}
    for mac, history in device_history.items():
        if mac not in current_macs:
            # Calculate time difference
            time_diff = (timestamp - history['last_seen']).total_seconds()
            # If last seen within the last 5 minutes, consider it recently disconnected
            if time_diff < 300:  # 5 minutes in seconds
                devices.append({
                    'mac': mac,
                    'ip': history['last_ip'],
                    'last_seen': history['last_seen'].strftime("%Y-%m-%d %H:%M:%S"),
                    'status': 'disconnected',
                    'time_since_disconnect': f"{int(time_diff)} seconds ago"
                })
    
    # Update global data
    devices_data = devices
    
    return devices

def continuous_scan(interval=30):
    """
    Continuously scan the network at specified intervals.
    
    Args:
        interval: Time between scans in seconds
    """
    global scanning_active
    
    while scanning_active:
        scan_network()
        time.sleep(interval)

@app.route('/')
def index():
    """Render the main dashboard page"""
    return render_template('index.html')

@app.route('/api/devices')
def get_devices():
    """API endpoint to get current devices data"""
    return jsonify({
        'devices': devices_data,
        'count': len(devices_data),
        'timestamp': scan_timestamp
    })

@app.route('/api/stats')
def get_stats():
    """API endpoint to get device statistics"""
    if not device_history:
        return jsonify({
            'total_unique_devices': 0,
            'active_devices': 0,
            'disconnected_devices': 0
        })
    
    active_count = sum(1 for device in devices_data if device['status'] == 'active')
    disconnected_count = sum(1 for device in devices_data if device['status'] == 'disconnected')
    
    return jsonify({
        'total_unique_devices': len(device_history),
        'active_devices': active_count,
        'disconnected_devices': disconnected_count,
        'new_devices': sum(1 for device in devices_data if device['status'] == 'new'),
        'moved_devices': sum(1 for device in devices_data if device['status'] == 'moved')
    })

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    """API endpoint to trigger a manual scan"""
    devices = scan_network()
    return jsonify({
        'success': True,
        'devices_found': len(devices)
    })

@app.route('/api/start_scanning/<int:interval>', methods=['POST'])
def start_scanning(interval):
    """API endpoint to start continuous scanning"""
    global scanning_active
    
    if scanning_active:
        return jsonify({'success': False, 'message': 'Scanning already active'})
    
    scanning_active = True
    scanner_thread = threading.Thread(target=continuous_scan, args=(interval,))
    scanner_thread.daemon = True
    scanner_thread.start()
    
    return jsonify({'success': True, 'message': f'Scanning started with {interval}s interval'})

@app.route('/api/stop_scanning', methods=['POST'])
def stop_scanning():
    """API endpoint to stop continuous scanning"""
    global scanning_active
    
    if not scanning_active:
        return jsonify({'success': False, 'message': 'Scanning not active'})
    
    scanning_active = False
    return jsonify({'success': True, 'message': 'Scanning stopped'})

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    # Create index.html template
    with open('templates/index.html', 'w') as f:
        f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Device Tracking Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding-top: 20px; }
        .status-active { color: green; }
        .status-disconnected { color: red; }
        .status-new { color: blue; }
        .status-moved { color: orange; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="mb-4">Emergency WiFi Device Tracking</h1>
        
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        Device Statistics
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-3">
                                <div class="card bg-light">
                                    <div class="card-body text-center">
                                        <h3 id="total-devices">-</h3>
                                        <p>Total Unique Devices</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card bg-success text-white">
                                    <div class="card-body text-center">
                                        <h3 id="active-devices">-</h3>
                                        <p>Active Devices</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card bg-danger text-white">
                                    <div class="card-body text-center">
                                        <h3 id="disconnected-devices">-</h3>
                                        <p>Disconnected Devices</p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="card bg-info text-white">
                                    <div class="card-body text-center">
                                        <h3 id="new-devices">-</h3>
                                        <p>New Devices</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mb-3">
            <div class="col-md-6">
                <button id="scan-btn" class="btn btn-primary me-2">Manual Scan</button>
                <button id="start-scan-btn" class="btn btn-success me-2">Start Auto Scan</button>
                <button id="stop-scan-btn" class="btn btn-danger" disabled>Stop Auto Scan</button>
            </div>
            <div class="col-md-6 text-end">
                <span>Last scan: <span id="last-scan-time">Never</span></span>
            </div>
        </div>
        
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Last Seen</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody id="devices-table">
                    <tr>
                        <td colspan="5" class="text-center">No devices found. Click "Manual Scan" to start.</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // Function to update the dashboard
        function updateDashboard() {
            fetch('/api/devices')
                .then(response => response.json())
                .then(data => {
                    // Update last scan time
                    if (data.timestamp) {
                        document.getElementById('last-scan-time').textContent = data.timestamp;
                    }
                    
                    // Update devices table
                    const tableBody = document.getElementById('devices-table');
                    if (data.devices.length === 0) {
                        tableBody.innerHTML = '<tr><td colspan="5" class="text-center">No devices found.</td></tr>';
                    } else {
                        tableBody.innerHTML = '';
                        data.devices.forEach(device => {
                            const row = document.createElement('tr');
                            
                            // Status column with icon
                            let statusClass = '', statusText = '';
                            switch (device.status) {
                                case 'active':
                                    statusClass = 'status-active';
                                    statusText = 'Active';
                                    break;
                                case 'disconnected':
                                    statusClass = 'status-disconnected';
                                    statusText = 'Disconnected';
                                    break;
                                case 'new':
                                    statusClass = 'status-new';
                                    statusText = 'New';
                                    break;
                                case 'moved':
                                    statusClass = 'status-moved';
                                    statusText = 'Moved';
                                    break;
                            }
                            
                            // Notes column
                            let notes = '';
                            if (device.status === 'disconnected' && device.time_since_disconnect) {
                                notes = `Disconnected ${device.time_since_disconnect}`;
                            } else if (device.status === 'moved') {
                                notes = 'IP Address changed';
                            } else if (device.status === 'new') {
                                notes = 'First time seen';
                            }
                            
                            row.innerHTML = `
                                <td><span class="${statusClass}">${statusText}</span></td>
                                <td>${device.ip}</td>
                                <td>${device.mac}</td>
                                <td>${device.last_seen}</td>
                                <td>${notes}</td>
                            `;
                            tableBody.appendChild(row);
                        });
                    }
                })
                .catch(error => console.error('Error fetching devices:', error));
            
            // Update statistics
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-devices').textContent = data.total_unique_devices;
                    document.getElementById('active-devices').textContent = data.active_devices;
                    document.getElementById('disconnected-devices').textContent = data.disconnected_devices;
                    document.getElementById('new-devices').textContent = data.new_devices;
                })
                .catch(error => console.error('Error fetching stats:', error));
        }
        
        // Manual scan button
        document.getElementById('scan-btn').addEventListener('click', () => {
            fetch('/api/scan', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateDashboard();
                }
            })
            .catch(error => console.error('Error triggering scan:', error));
        });
        
        // Start auto scan button
        document.getElementById('start-scan-btn').addEventListener('click', () => {
            const interval = 30; // 30 seconds between scans
            fetch(`/api/start_scanning/${interval}`, {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('start-scan-btn').disabled = true;
                    document.getElementById('stop-scan-btn').disabled = false;
                    // Set up auto refresh
                    window.autoRefreshInterval = setInterval(updateDashboard, interval * 1000);
                }
            })
            .catch(error => console.error('Error starting auto scan:', error));
        });
        
        // Stop auto scan button
        document.getElementById('stop-scan-btn').addEventListener('click', () => {
            fetch('/api/stop_scanning', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('start-scan-btn').disabled = false;
                    document.getElementById('stop-scan-btn').disabled = true;
                    // Clear auto refresh
                    clearInterval(window.autoRefreshInterval);
                }
            })
            .catch(error => console.error('Error stopping auto scan:', error));
        });
        
        // Initial update
        updateDashboard();
    </script>
</body>
</html>
        ''')
    
    print("Starting WiFi Device Tracking Dashboard...")
    print("Open http://127.0.0.1:5000 in your browser")
    app.run(debug=True)