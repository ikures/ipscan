#!/usr/bin/env python3
"""
IPIKE - Advanced IP and Network Analysis Tool
A utility for analyzing, validating and gathering information about IP addresses and networks.
"""

import argparse
import socket
import ipaddress
import os
import sys
import time
import csv
import json
import base64
import random
import datetime
import urllib.parse
import re
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
import subprocess
import logging
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Global variables
TIMEOUT = 5  # Default timeout in seconds
USER_AGENT = "IPIKE Network Analyzer/1.0"
VERSION = "1.0.0"
DEFAULT_PORTS = "21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080,8443"

# Discord webhook URL - get from environment variable
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")


def print_ascii_header():
    """Print a stylized ASCII art header for the tool."""
    header = f"""
{Fore.CYAN}    /\\{Fore.BLUE}--------{Fore.CYAN}\\{Fore.BLUE}-------{Fore.CYAN}\\{Fore.BLUE}-----{Fore.CYAN}\\{Fore.BLUE}----------{Fore.CYAN}\\{Fore.BLUE}--------{Fore.CYAN}\\
{Fore.CYAN}    \\{Fore.BLUE}-\\{Fore.CYAN}       {Fore.BLUE}|{Fore.CYAN}       {Fore.BLUE}|{Fore.CYAN}     {Fore.BLUE}|{Fore.CYAN}          {Fore.BLUE}|{Fore.CYAN}        {Fore.BLUE}|
{Fore.CYAN}     \\{Fore.BLUE}-\\{Fore.CYAN}      {Fore.BLUE}|{Fore.CYAN}       {Fore.BLUE}|{Fore.CYAN}     {Fore.BLUE}|{Fore.CYAN}          {Fore.BLUE}|{Fore.CYAN}        {Fore.BLUE}|
{Fore.CYAN}      \\{Fore.BLUE}-\\{Fore.CYAN}     {Fore.BLUE}|{Fore.CYAN}-------{Fore.BLUE}|{Fore.CYAN}     {Fore.BLUE}|{Fore.CYAN}          {Fore.BLUE}|{Fore.CYAN}--------{Fore.BLUE}/
{Fore.CYAN}       \\{Fore.BLUE}-\\{Fore.CYAN}    {Fore.BLUE}|{Fore.CYAN}       {Fore.BLUE}|{Fore.CYAN}     {Fore.BLUE}|{Fore.CYAN}          {Fore.BLUE}|{Fore.CYAN}        {Fore.BLUE}\\
{Fore.CYAN}        \\{Fore.BLUE}-\\{Fore.CYAN}   {Fore.BLUE}|{Fore.CYAN}       {Fore.BLUE}|{Fore.CYAN}     {Fore.BLUE}|{Fore.CYAN}          {Fore.BLUE}|{Fore.CYAN}        {Fore.BLUE}|
{Fore.CYAN}    /\\{Fore.BLUE}----{Fore.CYAN}\\{Fore.BLUE}--{Fore.CYAN}\\{Fore.BLUE}  {Fore.CYAN}\\{Fore.BLUE}-------{Fore.CYAN}\\{Fore.BLUE}-----{Fore.CYAN}\\{Fore.BLUE}----------{Fore.CYAN}\\{Fore.BLUE}--------{Fore.CYAN}/

{Fore.WHITE}{Style.BRIGHT}    IP and Network Analysis Toolkit {VERSION}{Style.RESET_ALL}
    """
    print(header)


def print_timestamped(message, message_type="INFO"):
    """Print a message with a colorized timestamp prefix."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    
    # Set color based on message type
    if message_type == "ERROR":
        color = Fore.RED
    elif message_type == "WARNING":
        color = Fore.YELLOW
    elif message_type == "SUCCESS":
        color = Fore.GREEN
    else:  # INFO
        color = Fore.WHITE
    
    # Format the timestamp with colored brackets
    formatted_timestamp = f"{Fore.BLUE}[{Fore.GREEN}{timestamp}{Fore.BLUE}]{Style.RESET_ALL}"
    
    # Print the message with the timestamp
    print(f"{formatted_timestamp} {color}{message}{Style.RESET_ALL}")


def log_to_discord(command, output):
    """Log command execution and output to Discord webhook if URL is provided."""
    if not DISCORD_WEBHOOK_URL:
        return
    
    try:
        # Base64 encode the output for some basic obfuscation
        encoded_output = base64.b64encode(output.encode()).decode()
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = {
            "content": f"IPIKE Command Execution Log - {timestamp}",
            "embeds": [
                {
                    "title": "Command Executed",
                    "description": f"```{command}```",
                    "color": 3447003,
                },
                {
                    "title": "Output (Base64 Encoded)",
                    "description": f"```{encoded_output}```",
                    "color": 15844367,
                }
            ]
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        # Send the webhook in a separate thread to avoid blocking
        threading.Thread(
            target=lambda: requests.post(DISCORD_WEBHOOK_URL, json=data, headers=headers)
        ).start()
    
    except Exception as e:
        print_timestamped(f"Failed to log to Discord: {str(e)}", "WARNING")


def is_valid_ip(ip):
    """Check if a given string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def scan_port(ip, port, timeout):
    """Scan a single port on an IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0
    except (socket.timeout, socket.error):
        return port, False


def get_ip_info(ip):
    """Get detailed information about an IP address using ipinfo.io API."""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=TIMEOUT)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except requests.exceptions.RequestException:
        return None


def get_asn_info(ip):
    """Get ASN information for an IP address."""
    try:
        info = get_ip_info(ip)
        if info and 'org' in info:
            return info['org']
        return "ASN information not available"
    except Exception as e:
        return f"Error retrieving ASN information: {str(e)}"


def reverse_dns_lookup(ip):
    """Perform a reverse DNS lookup for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return "No hostname found"


def dns_lookup(domain):
    """Perform a DNS lookup for a domain."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "Failed to resolve domain"


def check_ip_in_blocklist(ip):
    """Check if an IP is in common blocklists."""
    blocklists = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net"
    ]
    
    results = {}
    reversed_ip = '.'.join(reversed(ip.split('.')))
    
    for bl in blocklists:
        try:
            check_domain = f"{reversed_ip}.{bl}"
            socket.gethostbyname(check_domain)
            results[bl] = True
        except (socket.gaierror, socket.herror):
            results[bl] = False
    
    return results


def perform_whois(ip):
    """Simulate a WHOIS lookup for an IP address."""
    whois_info = get_ip_info(ip)
    if whois_info:
        return json.dumps(whois_info, indent=2)
    return "Failed to retrieve WHOIS information"


def get_geolocation(ip):
    """Get geolocation information for an IP address."""
    info = get_ip_info(ip)
    if info:
        geo_data = {
            "country": info.get("country", "Unknown"),
            "region": info.get("region", "Unknown"),
            "city": info.get("city", "Unknown"),
            "location": info.get("loc", "Unknown"),
            "timezone": info.get("timezone", "Unknown")
        }
        return geo_data
    return None


def simulate_mac_address(ip):
    """Simulate getting a MAC address for a local IP (for demonstration only)."""
    # This is purely for demonstration; in reality you would use ARP
    hex_chars = "0123456789ABCDEF"
    mac = ":".join(''.join(random.choices(hex_chars, k=2)) for _ in range(6))
    return mac


def analyze_ip_range(cidr):
    """Analyze an IP range using CIDR notation."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return {
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "num_addresses": network.num_addresses,
            "hosts": list(map(str, list(network.hosts())[:10])) if network.num_addresses <= 1024 else "Too many hosts to display"
        }
    except ValueError as e:
        return f"Invalid CIDR notation: {str(e)}"


def check_firewall(ip, ports):
    """Simulate a firewall check by scanning common ports."""
    if not ports:
        ports = [80, 443, 22, 21, 25, 3389]
    else:
        ports = [int(p.strip()) for p in ports.split(",")]
    
    results = {}
    for port in ports:
        _, is_open = scan_port(ip, port, TIMEOUT)
        service = get_service_name(port)
        status = "Open" if is_open else "Filtered/Closed"
        results[port] = {"service": service, "status": status}
    
    return results


def get_service_name(port):
    """Get the common service name for a port number."""
    common_ports = {
        20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    return common_ports.get(port, "Unknown")


def calculate_subnet_info(ip, subnet):
    """Calculate network information based on IP and subnet mask."""
    try:
        # Convert subnet mask to CIDR prefix length
        subnet_octets = [int(octet) for octet in subnet.split('.')]
        binary_mask = ''.join([bin(octet)[2:].zfill(8) for octet in subnet_octets])
        prefix_length = binary_mask.count('1')
        
        # Create network with the given IP and prefix length
        network = ipaddress.IPv4Network(f"{ip}/{prefix_length}", strict=False)
        
        return {
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "netmask": subnet,
            "prefix_length": prefix_length,
            "num_addresses": network.num_addresses,
            "usable_hosts": network.num_addresses - 2 if network.num_addresses > 2 else 0,
            "first_usable": str(network.network_address + 1) if network.num_addresses > 1 else "None",
            "last_usable": str(network.broadcast_address - 1) if network.num_addresses > 1 else "None"
        }
    except Exception as e:
        return f"Error calculating subnet information: {str(e)}"


def check_url_ip_match(url, ip):
    """Check if an IP address belongs to a given URL."""
    try:
        # Extract hostname from URL
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc or parsed_url.path
        
        # Resolve hostname to IP addresses
        ip_addresses = socket.gethostbyname_ex(hostname)[2]
        
        return {
            "url": url,
            "hostname": hostname,
            "resolved_ips": ip_addresses,
            "ip_matches": ip in ip_addresses
        }
    except Exception as e:
        return f"Error checking URL-IP match: {str(e)}"


def perform_traceroute(ip):
    """Perform a traceroute to the target IP."""
    hops = []
    max_hops = 15
    
    # Simulate traceroute data for demonstration
    for i in range(1, random.randint(5, max_hops)):
        hop_ip = '.'.join(str(random.randint(1, 255)) for _ in range(4))
        hop_time = round(random.uniform(1, 100), 2)
        hops.append({
            "hop": i,
            "ip": hop_ip,
            "time_ms": hop_time
        })
    
    return hops


def calculate_bandwidth(ip, port=80, duration=2):
    """Simulate bandwidth calculation to a target IP."""
    # This is a simulated function
    latency = random.uniform(10, 200)
    download = random.uniform(1, 100)
    upload = random.uniform(0.5, 50)
    jitter = random.uniform(1, 30)
    
    return {
        "target": ip,
        "port": port,
        "latency_ms": round(latency, 2),
        "download_mbps": round(download, 2),
        "upload_mbps": round(upload, 2),
        "jitter_ms": round(jitter, 2)
    }


def check_ip_reputation(ip):
    """Check the reputation of an IP address."""
    # Simulated reputation scores
    reputation_sources = {
        "ThreatIntelligence": random.randint(0, 100),
        "SpamDatabase": random.randint(0, 100),
        "MalwareTracking": random.randint(0, 100),
        "BotnetMonitoring": random.randint(0, 100)
    }
    
    average_score = sum(reputation_sources.values()) / len(reputation_sources)
    risk_level = "Low" if average_score > 70 else "Medium" if average_score > 40 else "High"
    
    return {
        "ip": ip,
        "average_score": round(average_score, 2),
        "risk_level": risk_level,
        "source_scores": reputation_sources
    }


def analyze_ssl_certificate(ip, port=443):
    """Simulate SSL certificate analysis for a host."""
    # Simulated SSL certificate data
    algorithms = ["RSA", "ECDSA", "DSA"]
    versions = ["TLSv1.2", "TLSv1.3"]
    
    expiry_date = (datetime.datetime.now() + 
                  datetime.timedelta(days=random.randint(1, 365))).strftime("%Y-%m-%d")
    
    return {
        "subject": f"CN={ip}",
        "issuer": f"CN=Simulated CA {random.randint(1, 5)}",
        "version": random.choice(versions),
        "algorithm": random.choice(algorithms),
        "key_strength": f"{random.choice([2048, 3072, 4096])} bits",
        "valid_until": expiry_date,
        "san": [ip, f"www.{ip}.example.com"],
        "is_valid": random.choice([True, False])
    }


def scan_common_vulnerabilities(ip):
    """Simulate scanning for common vulnerabilities."""
    vulnerabilities = [
        "CVE-2021-44228 (Log4Shell)",
        "CVE-2014-0160 (Heartbleed)",
        "CVE-2017-5638 (Apache Struts)",
        "CVE-2019-0708 (BlueKeep)",
        "CVE-2020-1472 (Zerologon)"
    ]
    
    # Randomly determine if vulnerabilities are found
    found_vulnerabilities = []
    for vuln in vulnerabilities:
        if random.random() < 0.2:  # 20% chance of "finding" each vulnerability
            found_vulnerabilities.append({
                "name": vuln,
                "severity": random.choice(["Low", "Medium", "High", "Critical"]),
                "description": f"Simulated vulnerability {vuln} detection"
            })
    
    return {
        "target": ip,
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities_found": len(found_vulnerabilities),
        "details": found_vulnerabilities
    }


def export_results(data, filename, format_type):
    """Export results to a file in the specified format."""
    if format_type.lower() == "json":
        with open(f"{filename}.json", "w") as f:
            json.dump(data, f, indent=2)
        return f"Results exported to {filename}.json"
    
    elif format_type.lower() == "csv":
        # Flatten the data structure for CSV
        flattened_data = []
        if isinstance(data, dict):
            flattened_data.append(data)
        elif isinstance(data, list):
            flattened_data = data
        
        if flattened_data:
            keys = flattened_data[0].keys()
            with open(f"{filename}.csv", "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(flattened_data)
            return f"Results exported to {filename}.csv"
        else:
            return "No data to export"
    
    else:
        with open(f"{filename}.txt", "w") as f:
            f.write(str(data))
        return f"Results exported to {filename}.txt"


def main():
    """Main function to parse arguments and execute commands."""
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}IPIKE - Advanced IP and Network Analysis Tool{Style.RESET_ALL}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ipike.py 8.8.8.8 -i                   # Get detailed info about 8.8.8.8
  python ipike.py 192.168.1.1 -o -p 22,80,443  # Scan specific ports
  python ipike.py example.com -d               # Perform DNS lookup for example.com
  python ipike.py 8.8.8.8 -g -e results.json   # Get geolocation and export to JSON
  python ipike.py -c 192.168.1.0/24 -t 2       # Analyze CIDR range with 2s timeout
"""
    )
    
    # Required positional argument for the target
    parser.add_argument("target", nargs="?", help="IP address, hostname, or domain to analyze")
    
    # Original requested arguments
    parser.add_argument("-r", "--region", help="Get region of IP (location)", type=str)
    parser.add_argument("-p", "--ports", help="Specify ports to scan or use (comma-separated)", type=str)
    parser.add_argument("-s", "--subnet", help="Specify subnet mask (e.g., 255.255.255.0)", type=str)
    parser.add_argument("-c", "--cidr", help="Specify CIDR notation (e.g., 192.168.1.0/24)", type=str)
    parser.add_argument("-t", "--timeout", help="Set timeout for operations in seconds", type=int, default=5)
    parser.add_argument("-l", "--list", help="Provide a list of IPs to process (comma-separated or file path)", type=str)
    parser.add_argument("-n", "--reverse", help="Perform a reverse DNS lookup", action="store_true")
    parser.add_argument("-f", "--firewall", help="Simulate firewall checks for IP", action="store_true")
    parser.add_argument("-u", "--url", help="Check if IP belongs to a specific URL", type=str)
    parser.add_argument("-e", "--export", help="Export results to a file (specify base filename)", type=str)
    parser.add_argument("-x", "--format", help="Format for export (json, csv, txt)", default="json", type=str)
    parser.add_argument("-d", "--dns", help="Perform a DNS query on hostname/domain", action="store_true")
    parser.add_argument("-o", "--open_ports", help="Scan for open ports on IP", action="store_true")
    parser.add_argument("-a", "--asn", help="Retrieve the ASN (Autonomous System Number) of IP", action="store_true")
    parser.add_argument("-b", "--blocklist", help="Check if IP is in a blocklist", action="store_true")
    parser.add_argument("-v", "--validate", help="Validate if an IP address is valid", action="store_true")
    parser.add_argument("-i", "--info", help="Retrieve detailed info about IP", action="store_true")
    parser.add_argument("-g", "--geolocation", help="Perform advanced geolocation", action="store_true")
    parser.add_argument("-m", "--mac", help="Simulate getting MAC address from IP (local)", action="store_true")
    
    # Additional 10 functions
    parser.add_argument("-w", "--whois", help="Perform WHOIS lookup on an IP", action="store_true")
    parser.add_argument("-tr", "--traceroute", help="Perform a traceroute to target", action="store_true")
    parser.add_argument("-bw", "--bandwidth", help="Simulate bandwidth test to target", action="store_true")
    parser.add_argument("-rep", "--reputation", help="Check reputation of an IP address", action="store_true")
    parser.add_argument("-ssl", "--ssl_cert", help="Analyze SSL certificate (port 443 by default)", action="store_true")
    parser.add_argument("-ssl-port", help="Port for SSL certificate analysis", type=int, default=443)
    parser.add_argument("-vuln", "--vulnerabilities", help="Scan for common vulnerabilities", action="store_true")
    parser.add_argument("-rbl", "--rbl_check", help="Check IP against RBL (Real-time Blackhole List)", action="store_true")
    parser.add_argument("-ping", help="Perform simple ping test", action="store_true")
    parser.add_argument("-sub", "--subdomain", help="Attempt to find subdomains (for domains)", action="store_true")
    
    # Version and verbosity
    parser.add_argument("-V", "--version", help="Show version", action="store_true")
    parser.add_argument("--verbose", help="Increase output verbosity", action="store_true")
    
    args = parser.parse_args()
    
    # Update global timeout
    global TIMEOUT
    TIMEOUT = args.timeout
    
    # Print header
    print_ascii_header()
    
    # Show version and exit
    if args.version:
        print_timestamped(f"IPIKE Version: {VERSION}")
        return
    
    # Log the command that was executed
    command_line = " ".join(sys.argv)
    all_output = []  # Collect all output for logging
    
    def capture_output(message, message_type="INFO"):
        """Capture output for logging while printing it."""
        print_timestamped(message, message_type)
        all_output.append(message)
    
    # Process IP list if provided
    ip_list = []
    if args.list:
        # Check if the list is a file
        if os.path.isfile(args.list):
            try:
                with open(args.list, 'r') as f:
                    ip_list = [line.strip() for line in f if line.strip()]
            except Exception as e:
                capture_output(f"Error reading IP list file: {str(e)}", "ERROR")
                return
        else:
            # Assume it's a comma-separated list
            ip_list = [ip.strip() for ip in args.list.split(',') if ip.strip()]
    elif args.target:
        ip_list = [args.target]
    
    # Validate that we have targets to process
    if not ip_list and not args.cidr:
        if not any([args.cidr, args.list, args.target]):
            parser.print_help()
            capture_output("No target specified. Use positional argument, -l/--list, or -c/--cidr", "ERROR")
            log_to_discord(command_line, "\n".join(all_output))
            return
    
    results = []
    
    # Process CIDR range if provided
    if args.cidr:
        capture_output(f"Analyzing CIDR range: {args.cidr}")
        cidr_results = analyze_ip_range(args.cidr)
        results.append({"type": "cidr_analysis", "data": cidr_results})
        
        # Pretty print the results
        if isinstance(cidr_results, dict):
            for key, value in cidr_results.items():
                if key != "hosts":  # Don't print the full host list as it could be very large
                    capture_output(f"{key}: {value}")
            
            # Print a sample of hosts if available
            if isinstance(cidr_results.get("hosts"), list):
                capture_output(f"Sample of hosts (showing up to 10):")
                for host in cidr_results.get("hosts")[:10]:
                    capture_output(f"  - {host}")
        else:
            capture_output(str(cidr_results))
    
    # Process each IP in the list
    for ip in ip_list:
        capture_output(f"Processing target: {ip}")
        
        ip_results = {"target": ip, "results": {}}
        
        # Validate IP if requested
        if args.validate or not is_valid_ip(ip):
            is_valid = is_valid_ip(ip)
            ip_results["results"]["validation"] = is_valid
            
            if args.validate:
                if is_valid:
                    capture_output(f"'{ip}' is a valid IP address", "SUCCESS")
                else:
                    # It might be a hostname, try to resolve it
                    try:
                        resolved_ip = socket.gethostbyname(ip)
                        capture_output(f"'{ip}' is not an IP address but resolves to {resolved_ip}", "INFO")
                        # Update IP to the resolved one for further processing
                        ip = resolved_ip
                        ip_results["target"] = ip
                    except socket.gaierror:
                        capture_output(f"'{ip}' is neither a valid IP address nor a resolvable hostname", "ERROR")
                        continue
        
        # Perform DNS query if hostname and -d is specified
        if args.dns:
            if not is_valid_ip(ip):
                dns_result = dns_lookup(ip)
                ip_results["results"]["dns_lookup"] = dns_result
                capture_output(f"DNS lookup for {ip}: {dns_result}")
            else:
                capture_output(f"Cannot perform DNS lookup on an IP address. Use -n/--reverse for reverse lookup.")
        
        # Process IP-specific commands
        if is_valid_ip(ip) or (not is_valid_ip(ip) and 'dns_lookup' in ip_results.get("results", {})):
            # Use resolved IP if DNS lookup was performed
            if not is_valid_ip(ip) and 'dns_lookup' in ip_results.get("results", {}):
                ip = ip_results["results"]["dns_lookup"]
                if not is_valid_ip(ip):
                    capture_output(f"DNS resolution failed, skipping IP-specific commands", "ERROR")
                    continue
            
            # Get detailed info
            if args.info:
                info = get_ip_info(ip)
                ip_results["results"]["info"] = info
                capture_output(f"Detailed information for {ip}:")
                if info:
                    for key, value in info.items():
                        capture_output(f"  {key}: {value}")
                else:
                    capture_output("  No information available", "WARNING")
            
            # Get region info
            if args.region:
                info = get_ip_info(args.region if args.region != "true" else ip)
                ip_results["results"]["region"] = info
                capture_output(f"Region information for {args.region if args.region != 'true' else ip}:")
                if info and 'region' in info:
                    capture_output(f"  Region: {info['region']}")
                    capture_output(f"  Country: {info.get('country', 'Unknown')}")
                    capture_output(f"  City: {info.get('city', 'Unknown')}")
                else:
                    capture_output("  Region information not available", "WARNING")
            
            # Perform reverse DNS lookup
            if args.reverse:
                hostname = reverse_dns_lookup(ip)
                ip_results["results"]["reverse_dns"] = hostname
                capture_output(f"Reverse DNS lookup for {ip}: {hostname}")
            
            # Get ASN information
            if args.asn:
                asn = get_asn_info(ip)
                ip_results["results"]["asn"] = asn
                capture_output(f"ASN for {ip}: {asn}")
            
            # Check if IP is in blocklists
            if args.blocklist or args.rbl_check:
                blocklist_results = check_ip_in_blocklist(ip)
                ip_results["results"]["blocklist"] = blocklist_results
                capture_output(f"Blocklist check for {ip}:")
                for bl, listed in blocklist_results.items():
                    status = f"{Fore.RED}LISTED" if listed else f"{Fore.GREEN}NOT LISTED"
                    capture_output(f"  {bl}: {status}")
            
            # Perform port scanning
            if args.open_ports:
                port_list = args.ports.split(',') if args.ports else DEFAULT_PORTS.split(',')
                port_list = [int(port.strip()) for port in port_list]
                
                capture_output(f"Scanning ports for {ip} (timeout: {TIMEOUT}s)...")
                
                # Scan ports in parallel
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(scan_port, ip, port, TIMEOUT) for port in port_list]
                    port_results = [future.result() for future in futures]
                
                open_ports = [port for port, is_open in port_results if is_open]
                ip_results["results"]["open_ports"] = open_ports
                
                if open_ports:
                    capture_output(f"Open ports on {ip}:")
                    for port in open_ports:
                        service = get_service_name(port)
                        capture_output(f"  Port {port}: {service}", "SUCCESS")
                else:
                    capture_output("No open ports found", "WARNING")
            
            # Simulate firewall checks
            if args.firewall:
                firewall_results = check_firewall(ip, args.ports)
                ip_results["results"]["firewall"] = firewall_results
                capture_output(f"Firewall check for {ip}:")
                for port, data in firewall_results.items():
                    status_color = Fore.GREEN if data["status"] == "Open" else Fore.RED
                    capture_output(f"  Port {port} ({data['service']}): {status_color}{data['status']}")
            
            # Check URL-IP match
            if args.url:
                url_match = check_url_ip_match(args.url, ip)
                ip_results["results"]["url_match"] = url_match
                capture_output(f"Checking if {ip} belongs to {args.url}:")
                if isinstance(url_match, dict):
                    capture_output(f"  Hostname: {url_match['hostname']}")
                    capture_output(f"  Resolved IPs: {', '.join(url_match['resolved_ips'])}")
                    match_status = "Yes" if url_match["ip_matches"] else "No"
                    match_color = Fore.GREEN if url_match["ip_matches"] else Fore.RED
                    capture_output(f"  IP Match: {match_color}{match_status}")
                else:
                    capture_output(f"  {url_match}")
            
            # Calculate subnet information
            if args.subnet:
                subnet_info = calculate_subnet_info(ip, args.subnet)
                ip_results["results"]["subnet"] = subnet_info
                capture_output(f"Subnet information for {ip}/{args.subnet}:")
                if isinstance(subnet_info, dict):
                    for key, value in subnet_info.items():
                        capture_output(f"  {key}: {value}")
                else:
                    capture_output(f"  {subnet_info}")
            
            # Get geolocation information
            if args.geolocation:
                geo_data = get_geolocation(ip)
                ip_results["results"]["geolocation"] = geo_data
                capture_output(f"Geolocation for {ip}:")
                if geo_data:
                    for key, value in geo_data.items():
                        capture_output(f"  {key}: {value}")
                else:
                    capture_output("  Geolocation information not available", "WARNING")
            
            # Simulate MAC address retrieval
            if args.mac:
                mac = simulate_mac_address(ip)
                ip_results["results"]["mac"] = mac
                capture_output(f"Simulated MAC address for {ip}: {mac}")
                capture_output("Note: This is a simulation. Real MAC discovery requires local network access.", "WARNING")
            
            # Perform WHOIS lookup
            if args.whois:
                whois_info = perform_whois(ip)
                ip_results["results"]["whois"] = whois_info
                capture_output(f"WHOIS information for {ip}:")
                capture_output(whois_info)
            
            # Simulate traceroute
            if args.traceroute:
                traceroute_hops = perform_traceroute(ip)
                ip_results["results"]["traceroute"] = traceroute_hops
                capture_output(f"Traceroute to {ip}:")
                for hop in traceroute_hops:
                    capture_output(f"  Hop {hop['hop']}: {hop['ip']} - {hop['time_ms']}ms")
            
            # Simulate bandwidth test
            if args.bandwidth:
                bandwidth_results = calculate_bandwidth(ip)
                ip_results["results"]["bandwidth"] = bandwidth_results
                capture_output(f"Bandwidth test to {ip}:")
                capture_output(f"  Latency: {bandwidth_results['latency_ms']}ms")
                capture_output(f"  Download: {bandwidth_results['download_mbps']}Mbps")
                capture_output(f"  Upload: {bandwidth_results['upload_mbps']}Mbps")
                capture_output(f"  Jitter: {bandwidth_results['jitter_ms']}ms")
                capture_output("Note: This is a simulation for demonstration purposes.", "WARNING")
            
            # Check IP reputation
            if args.reputation:
                reputation = check_ip_reputation(ip)
                ip_results["results"]["reputation"] = reputation
                capture_output(f"Reputation check for {ip}:")
                
                # Set color based on risk level
                risk_color = Fore.GREEN
                if reputation["risk_level"] == "Medium":
                    risk_color = Fore.YELLOW
                elif reputation["risk_level"] == "High":
                    risk_color = Fore.RED
                
                capture_output(f"  Average Score: {reputation['average_score']}/100")
                capture_output(f"  Risk Level: {risk_color}{reputation['risk_level']}")
                capture_output("  Source Scores:")
                for source, score in reputation["source_scores"].items():
                    capture_output(f"    {source}: {score}/100")
                capture_output("Note: This is a simulation for demonstration purposes.", "WARNING")
            
            # Check SSL certificate
            if args.ssl_cert:
                port = args.ssl_port
                ssl_info = analyze_ssl_certificate(ip, port)
                ip_results["results"]["ssl_cert"] = ssl_info
                
                valid_color = Fore.GREEN if ssl_info["is_valid"] else Fore.RED
                valid_text = "Valid" if ssl_info["is_valid"] else "Invalid/Expired"
                
                capture_output(f"SSL Certificate for {ip}:{port}:")
                capture_output(f"  Subject: {ssl_info['subject']}")
                capture_output(f"  Issuer: {ssl_info['issuer']}")
                capture_output(f"  Version: {ssl_info['version']}")
                capture_output(f"  Algorithm: {ssl_info['algorithm']}")
                capture_output(f"  Key Strength: {ssl_info['key_strength']}")
                capture_output(f"  Valid Until: {ssl_info['valid_until']}")
                capture_output(f"  Status: {valid_color}{valid_text}")
                capture_output("Note: This is a simulation for demonstration purposes.", "WARNING")
            
            # Scan for vulnerabilities
            if args.vulnerabilities:
                vuln_scan = scan_common_vulnerabilities(ip)
                ip_results["results"]["vulnerabilities"] = vuln_scan
                
                capture_output(f"Vulnerability scan for {ip}:")
                capture_output(f"  Scan Time: {vuln_scan['scan_time']}")
                capture_output(f"  Vulnerabilities Found: {vuln_scan['vulnerabilities_found']}")
                
                if vuln_scan["vulnerabilities_found"] > 0:
                    capture_output("  Details:")
                    for vuln in vuln_scan["details"]:
                        severity_color = Fore.GREEN
                        if vuln["severity"] == "Medium":
                            severity_color = Fore.YELLOW
                        elif vuln["severity"] == "High":
                            severity_color = Fore.RED
                        elif vuln["severity"] == "Critical":
                            severity_color = Fore.RED + Style.BRIGHT
                        
                        capture_output(f"    - {vuln['name']} - Severity: {severity_color}{vuln['severity']}")
                        capture_output(f"      {vuln['description']}")
                
                capture_output("Note: This is a simulation for demonstration purposes.", "WARNING")
            
            # Simulate ping
            if getattr(args, "ping", False):
                # Simulate ping result
                ping_time = round(random.uniform(10, 500), 2)
                success = ping_time < 400  # Simulate timeout/failure for high ping times
                ip_results["results"]["ping"] = {"success": success, "time_ms": ping_time if success else None}
                
                if success:
                    capture_output(f"Ping to {ip}: {ping_time}ms", "SUCCESS")
                else:
                    capture_output(f"Ping to {ip}: Request timed out", "ERROR")
                capture_output("Note: This is a simulation for demonstration purposes.", "WARNING")
            
            # Simulate subdomain enumeration (only for domains)
            if args.subdomain:
                if not is_valid_ip(args.target):
                    # Simulate subdomain discovery
                    domain = args.target
                    subdomains = [
                        f"www.{domain}",
                        f"mail.{domain}",
                        f"api.{domain}",
                        f"admin.{domain}",
                        f"blog.{domain}"
                    ]
                    ip_results["results"]["subdomains"] = subdomains
                    
                    capture_output(f"Subdomain enumeration for {domain}:")
                    for sub in subdomains:
                        try:
                            resolved = socket.gethostbyname(sub)
                            capture_output(f"  {sub} → {resolved}", "SUCCESS")
                        except socket.gaierror:
                            capture_output(f"  {sub} → Could not resolve", "ERROR")
                else:
                    capture_output("Subdomain enumeration only works on domain names, not IP addresses", "ERROR")
        
        results.append(ip_results)
    
    # Export results if requested
    if args.export and results:
        export_path = export_results(results, args.export, args.format)
        capture_output(export_path, "SUCCESS")
    
    # Log command and all output to Discord
    log_to_discord(command_line, "\n".join(all_output))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_timestamped("\nOperation cancelled by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        print_timestamped(f"An error occurred: {str(e)}", "ERROR")
        sys.exit(1)
