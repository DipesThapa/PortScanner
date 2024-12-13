import subprocess
import sys
import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_output):
    """Parse Nmap XML output and print a structured summary."""
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        print("[-] Failed to parse Nmap XML output.")
        return

    host = root.find('host')
    if host is None:
        print("[-] No host information found.")
        return

    # Host State
    status_el = host.find('status')
    if status_el is not None:
        state = status_el.get('state')
        print(f"[*] Host State: {state}")

    # IP Address
    address_el = host.find('address')
    ip_address = address_el.get('addr') if address_el is not None else 'Unknown'
    print(f"[*] IP Address: {ip_address}")

    # Hostnames
    hostnames_el = host.find('hostnames')
    if hostnames_el is not None:
        host_names = [hn.get('name') for hn in hostnames_el.findall('hostname') if hn.get('name')]
        if host_names:
            print(f"[*] Hostnames: {', '.join(host_names)}")

    # OS Detection
    os_el = host.find('os')
    if os_el is not None:
        os_matches = os_el.findall('osmatch')
        if os_matches:
            # Print the best guess
            best_match = os_matches[0].get('name')
            accuracy = os_matches[0].get('accuracy')
            print(f"[*] OS Guess: {best_match} (Accuracy: {accuracy}%)")

    # Ports and Services
    ports_el = host.find('ports')
    if ports_el is not None:
        open_ports = []
        for p in ports_el.findall('port'):
            port_id = p.get('portid')
            protocol = p.get('protocol')
            state_el = p.find('state')
            service_el = p.find('service')

            if state_el is not None and state_el.get('state') == 'open':
                service_name = service_el.get('name') if service_el is not None else 'unknown'
                product = service_el.get('product') if service_el is not None else ''
                version = service_el.get('version') if service_el is not None else ''
                open_ports.append((port_id, protocol, service_name, product, version))

        if open_ports:
            print("\n[+] Open Ports and Detected Services:")
            for port_info in open_ports:
                port_id, protocol, service_name, product, version = port_info
                service_str = service_name
                if product or version:
                    service_str += f" ({product} {version})".strip()
                print(f"    - {protocol}/{port_id}: {service_str}")

    # Hostscript outputs (e.g., vulnerability checks)
    for hostscript in host.findall('hostscript'):
        for script_el in hostscript.findall('script'):
            script_id = script_el.get('id')
            output = script_el.get('output')
            print(f"\n[*] Host Script: {script_id}")
            print(f"    Output: {output}")

    # Port-specific scripts
    if ports_el is not None:
        for port_el in ports_el.findall('port'):
            for script_el in port_el.findall('script'):
                script_id = script_el.get('id')
                output = script_el.get('output')
                print(f"\n[*] Port {port_el.get('portid')} Script: {script_id}")
                print(f"    Output: {output}")

def run_nmap(target, start_port=1, end_port=1024):
    port_range = f"{start_port}-{end_port}"

    # Comprehensive scan: Aggressive (-A) + Vulnerability scripts (--script=vuln)
    command = ["nmap", "-A", "--script=vuln", "-p", port_range, "-oX", "-", target]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print("[-] Nmap not found. Please install nmap and try again.")
        sys.exit()

    if result.returncode != 0 and result.stderr:
        print("[-] Nmap scan encountered an error:")
        print(result.stderr.strip())
        return

    # Parse the XML output
    parse_nmap_xml(result.stdout)

if __name__ == "__main__":
    # Interactive prompts for target and optional port range
    target = input("Enter the target hostname or IP: ").strip()

    custom_range = input("Would you like to specify a custom port range? (y/n): ").strip().lower()
    if custom_range == 'y':
        start = input("Enter the start port (default is 1): ").strip()
        end = input("Enter the end port (default is 1024): ").strip()

        try:
            start_port = int(start) if start else 1
            end_port = int(end) if end else 1024
        except ValueError:
            print("[-] Invalid port number. Using default values (1-1024).")
            start_port, end_port = 1, 1024
    else:
        start_port, end_port = 1, 1024

    run_nmap(target, start_port, end_port)

