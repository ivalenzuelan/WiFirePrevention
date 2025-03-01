WiFi Device Tracking for Emergency Situations (WiFirePrevention)
=============================================

Project Overview
----------------

This project is designed to assist emergency responders by tracking the number of devices (representing people) inside a building based on WiFi connectivity. The system provides real-time monitoring of movement patterns using signal strength analysis and a web-based dashboard.

Goal
----

*   Track the number of devices (people) inside a building based on WiFi connectivity.
    
*   Monitor movement by analyzing signal strength (RSSI) or reconnect events.
    
*   Provide a simple dashboard for emergency responders to visualize movement trends.
    

How It Works
------------

1.  **Device Detection**: Scans the WiFi network for connected devices using ARP requests or router APIs.
    
2.  **Movement Tracking**: Estimates movement based on signal strength (RSSI) changes or disconnection/reconnection events.
    
3.  **Dashboard**: Displays real-time device count and movement trends for emergency response teams.
    

Tech Stack & Tools
------------------

### Backend:

*   Python (Flask/Django) or Node.js
    

### Network Scanning:

*   **Python**: scapy, arp-scan, or airodump-ng (Linux)
    
*   **Router API** (if accessible)
    

### Frontend:

*   Web dashboard using React, Vue.js, or simple HTML+JavaScript
    

### Database:

*   SQLite or Firebase (for real-time updates)
    

Basic Steps to Build It
-----------------------

### 1\. Scan for Connected Devices:

*   Use arp-scan (Linux/macOS) or nmap to list devices connected to the WiFi.
    
*   If router access is available, use its API to retrieve connected devices.
    

### 2\. Estimate Movement:

*   Track signal strength (RSSI) of connected devices.
    
*   Detect disconnection/reconnection events to infer movement.
    

### 3\. Build the Dashboard:

*   Display device count and movement logs in real-time.
    
*   Use WebSockets or Firebase for continuous updates.
    

Extra Features (Optional)
-------------------------

*   **Alert System**: Notify emergency responders if a person remains stationary for too long.
    
*   **Mobile App Version**: Provide real-time tracking via a mobile application.
    
*   **AI-Based Movement Prediction**: Use historical data to predict movement patterns and enhance response efficiency.
    

Installation & Setup
--------------------

### Prerequisites

Ensure you have the following installed:

*   Python 3.7+
    
*   pip package manager
    
*   virtualenv (recommended for an isolated environment)
    
*   scapy for packet sniffing
    
*   Flask or Django for the web server
    
*   requests for API communication
    

### Setting Up

1.  git clone https://github.com/your-repo/wifi-tracking.gitcd wifi-tracking
    
2.  python3 -m venv venvsource venv/bin/activate # On Windows: venv\\Scripts\\activate
    
3.  pip install -r requirements.txt
    

Usage
-----

### 1\. Start a Tracking Node

Run the following command on a WiFi-enabled device:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   sudo python node.py -i wlan0 -s http://your-server-ip:5000   `

Replace wlan0 with your WiFi interface and your-server-ip with the Flask server address.

### 2\. Start the Central Server

Run this command on the central server:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   python server.py   `

The server will listen for incoming data from nodes and process device locations.

### 3\. Run the Web Dashboard

Launch the Flask web app:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   python dashboard.py   `

Then, open http://127.0.0.1:5000 in your browser to view real-time tracking data.

API Endpoints
-------------

*   POST /api/node\_data - Receives tracking data from nodes.
    
*   GET /api/devices - Fetches all tracked devices.
    
*   GET /api/stats - Returns tracking statistics.
    
*   POST /api/start\_scanning/ - Starts continuous scanning.
    
*   POST /api/stop\_scanning - Stops scanning.
    
*   POST /api/scan - Triggers a manual scan.
    

Troubleshooting
---------------

*   sudo airmon-ng start wlan0
    
*   **Permission denied errors?** Run with sudo.
    
*   **Web app not loading?** Check if Flask is running and listening on the correct port.
    

Future Enhancements
-------------------

*   Implement Kalman filtering for RSSI smoothing.
    
*   Add WebSocket-based real-time updates.
    
*   Improve accuracy using machine learning models.
    

License
-------

This project is licensed under the MIT License.