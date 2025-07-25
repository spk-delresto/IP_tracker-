# IP_tracker-
# 🌐 IP Address Tracker & Threat Analyzer

**A Python-powered tool to investigate IP addresses, assess risks, and extract network context—useful for cybersecurity, IT admin, and threat intelligence.**

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## 🔥 Features
- **Geolocation Lookup** (Country, City, ISP, ASN)  
- **Threat Assessment** (Proxy, VPN, Hosting, TOR, Malware IPs)  
- **Local Network Scanning** (MAC, Hostname for private IPs)  
- **Business Context** (ASN, Org, Contact via RDAP)  
- **User-Friendly Output** (PrettyTable, Google Maps link)  

## 📦 Installation
```bash
git clone https://github.com/spk-delresto/IP_tracker-.git
cd ip_tracker

import requests
import ipaddress
import socket
import subprocess
import platform
from prettytable import PrettyTable
from ipwhois import IPWhois

# 🚨 Manually known high-risk IPs for demonstration/simulation
very_high_threat_ips = {
    "185.234.219.244",  # Known malware/C2
    "45.9.148.235",     # Spam source
    "194.26.29.16",     # Brute force activity
    "198.144.121.93",   # Phishing host
    "185.220.100.254"   # TOR exit node
}

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_mac_address(ip):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        subprocess.call(["ping", param, "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        arp_cmd = "arp -a" if platform.system().lower() == "windows" else "arp -n"
        arp_output = subprocess.check_output(arp_cmd.split(), universal_newlines=True)
        for line in arp_output.splitlines():
            if ip in line:
                parts = line.split()
                return parts[1] if platform.system().lower() == "windows" else parts[2]
        return "Unknown"
    except Exception as e:
        return f"Unknown ({e})"

def locate_private_ip(ip):
    print(f"\n🔎 Scanning local network for: {ip}")
    hostname = get_hostname(ip)
    mac = get_mac_address(ip)

    table = PrettyTable()
    table.field_names = ["Field", "Value"]
    table.add_row(["IP Address", ip])
    table.add_row(["Hostname", hostname])
    table.add_row(["MAC Address", mac])
    print(table)

def get_ip_info(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=66846719")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"status": "fail", "message": str(e)}

def assess_threat_level(data):
    ip = data.get("query", "")
    if ip in very_high_threat_ips:
        return "🔴 Very High Risk"

    threat_score = 0
    if data.get("proxy"):
        threat_score += 2
    if data.get("hosting"):
        threat_score += 2
    if data.get("mobile"):
        threat_score += 1

    isp = data.get("isp", "").lower()
    suspicious_keywords = ["vpn", "hosting", "data center", "cloud", "anonymous", "tor", "vps", "digitalocean"]
    if any(word in isp for word in suspicious_keywords):
        threat_score += 2

    if threat_score >= 5:
        return "🔴 Very High Risk"
    elif 3 <= threat_score < 5:
        return "⚠️ Medium Risk"
    elif 1 <= threat_score < 3:
        return "🟡 Low Risk"
    else:
        return "✅ Safe / Normal"

def display_ip_info(data):
    if data.get("status") == "fail":
        print(f"\n❌ Error: {data.get('message', 'Unknown error')}")
        return

    threat_level = assess_threat_level(data)

    table = PrettyTable()
    table.field_names = ["Field", "Value"]
    table.align["Field"] = "l"
    table.align["Value"] = "l"

    table.add_row(["IP Address", data.get("query", "N/A")])
    table.add_row(["Status", data.get("status", "N/A")])
    table.add_row(["Country", data.get("country", "N/A")])
    table.add_row(["Region", data.get("regionName", "N/A")])
    table.add_row(["City", data.get("city", "N/A")])
    table.add_row(["ZIP Code", data.get("zip", "N/A")])
    table.add_row(["Latitude", data.get("lat", "N/A")])
    table.add_row(["Longitude", data.get("lon", "N/A")])
    table.add_row(["Timezone", data.get("timezone", "N/A")])
    table.add_row(["ISP", data.get("isp", "N/A")])
    table.add_row(["Organization", data.get("org", "N/A")])
    table.add_row(["AS Number", data.get("as", "N/A")])
    table.add_row(["AS Name", data.get("asname", "N/A")])
    table.add_row(["Reverse DNS", data.get("reverse", "N/A")])
    table.add_row(["Mobile", "Yes" if data.get("mobile") else "No"])
    table.add_row(["Proxy", "Yes" if data.get("proxy") else "No"])
    table.add_row(["Hosting", "Yes" if data.get("hosting") else "No"])
    table.add_row(["Threat Level", threat_level])

    print("\n🌐 Public IP Information:")
    print(table)

    if data.get("lat") and data.get("lon"):
        print(f"\n📍 Google Maps: https://www.google.com/maps?q={data['lat']},{data['lon']}")

def get_business_context(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()

        table = PrettyTable()
        table.field_names = ["Business Context", "Value"]

        org_name = result.get("network", {}).get("name", "N/A")
        cidr = result.get("network", {}).get("cidr", "N/A")
        asn = result.get("asn", "N/A")
        asn_description = result.get("asn_description", "N/A")
        ip_range = result.get("network", {}).get("cidr", "N/A")
        contact_email = "N/A"

        for contact in result.get("objects", {}).values():
            roles = contact.get("roles", [])
            if "technical" in roles:
                contact_email = contact.get("contact", {}).get("email", "N/A")
                break

        table.add_row(["Organization", asn_description])
        table.add_row(["Network Name", org_name])
        table.add_row(["ASN Description", f"{asn} {asn_description}"])
        table.add_row(["IP Range", ip_range])
        table.add_row(["CIDR Block", cidr])
        table.add_row(["Technical Contact", contact_email])

        print("\n🏢 Business Network Context:")
        print(table)

    except Exception as e:
        print(f"❌ Error fetching business info: {e}")

def main():
    print("📡 IP Address Tracker")
    print("----------------------")

    while True:
        ip = input("\n🔹 Enter an IP address (or 'q' to quit): ").strip()

        if ip.lower() == 'q':
            print("👋 Exiting. Goodbye!")
            break

        if not is_valid_ip(ip):
            print("❌ Invalid IP address format.")
            continue

        if is_private_ip(ip):
            locate_private_ip(ip)
        else:
            data = get_ip_info(ip)
            display_ip_info(data)
            get_business_context(ip)

        again = input("\n🔄 Look up another IP? (y/n): ").lower()
        if again != 'y':
            print("👋 Thanks for using IP Tracker!")
            break

if __name__ == "__main__":
    try:
        import requests
        from prettytable import PrettyTable
        from ipwhois import IPWhois
    except ImportError:
        print("Installing required packages...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "prettytable", "ipwhois"])

    main()
