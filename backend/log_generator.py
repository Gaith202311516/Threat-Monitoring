import time
import random
import urllib.request
import urllib.parse

IPS = ["192.168.1.15", "10.0.0.55", "192.168.1.50", "172.16.0.4", "10.0.0.99"]
EVENT_TYPES = ["connection", "failed_login", "port_scan", "firewall_block", "login_failed"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]

API_URL = "http://127.0.0.1:8000/api/ingest/log"

print("🚀 Starting Traffic & Threat Generator... (Press CTRL+C to stop)")

while True:
    try:
        ip = random.choice(IPS)
        event = random.choice(EVENT_TYPES)
        severity = random.choice(SEVERITIES)
        
        raw_message = f"{ip} {event} {severity}"
        
        params = urllib.parse.urlencode({'raw_message': raw_message})
        full_url = f"{API_URL}?{params}"
        
        req = urllib.request.Request(full_url, method='POST')
        with urllib.request.urlopen(req) as response:
            res_data = response.read().decode('utf-8')
            print(f"Sent: {raw_message} -> Response: {res_data}")

    except Exception as e:
        print(f"Error sending log: {e}")

    time.sleep(1.5)
