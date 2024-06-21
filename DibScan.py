#!/usr/bin/env python3
import subprocess
import re
import uuid
from collections import Counter
import os
import time
import itertools
import threading
import sys


class OutputHandler:
    @staticmethod
    def remove_ansi_escape(text):
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)

    @staticmethod
    def write_to_file(filename, content):
        current_directory = os.getcwd()
        print(f"[+] Writing {filename} to {current_directory}...")
        with open(filename, 'w') as f:
            f.write(content)


class Scanner:
    def __init__(self, host):
        self.host = host
        self.output_handler = OutputHandler()

    def rust_scan(self):
        print(f"[+] Working on RustScan of {self.host}...")
        container_name = f'rustscan_{uuid.uuid4()}'
        command = ['docker', 'run', '--rm',
                   '--name', container_name, 'rustscan/rustscan:2.1.1',
                   '-a', self.host, '--', '-A', '-sV', '-sC']
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.stdout:
                clean_stdout = self.output_handler.remove_ansi_escape(result.stdout)
                print("[*] RustScan Output:\n", clean_stdout)
                self.output_handler.write_to_file("RustScan_results.txt", clean_stdout)

                # Extract domain from RustScan output
                domain = self.extract_domain_from_rustscan(clean_stdout)
                if domain:
                    self.update_etc_hosts(self.host, domain)
                    return clean_stdout, domain  # Return the extracted domain to be used in FFUF

            if result.stderr:
                print("[-] Standard Error:\n", result.stderr)

            return None, None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None, None

    def nmap_scan(self):
        print(f"[*] Running Nmap scan on {self.host}...")
        command = ['nmap', '-A', '-T4', self.host]
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.stdout:
                self.output_handler.write_to_file("Nmap_results.txt", result.stdout)

            return result.stdout

        except Exception as e:
            print(f"[-] An error occurred: {e}")
            return None

    def ffuf_directory_scan(self, host_or_domain, wordlist):
        print(f"[*] Running FFUF directory scan on {host_or_domain}...")
        target = f'http://{host_or_domain}/FUZZ'
        command = ['ffuf', '-w', f'{wordlist}:FUZZ', '-u', target]
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.stdout:
                clean_ffuf_output = self.output_handler.remove_ansi_escape(result.stdout)
                self.output_handler.write_to_file("Raw_FFUF_results.txt", clean_ffuf_output)

                common_size = self.identify_common_size(clean_ffuf_output)
                print(f"[!] Most common size to filter: {common_size}")

                if common_size:
                    filtered_command = command + ['-fs', str(common_size)]
                    filtered_result = subprocess.run(filtered_command, capture_output=True, text=True)
                    if filtered_result.stdout:
                        clean_filtered_output = self.output_handler.remove_ansi_escape(filtered_result.stdout)
                        print(f"[*] Initiating new FFUF scan to filter out response size {common_size}...\n")
                        self.output_handler.write_to_file("Filtered_FFUF_results.txt", clean_filtered_output)
                        print("[*] Filtered FFUF Output:\n", clean_filtered_output)
                    else:
                        print("[-] No filtered output from FFUF scan containing enumerated directories.\n"
                              "It is possible no web directories exist. Check for Vhosts/Subdomains.\n")
                else:
                    print("[-] No common size found in FFUF output.")
            else:
                print("[-] No output from FFUF scan.")

            return clean_ffuf_output
        except Exception as e:
            print(f"[-] An error occurred: {e}")
            return None

    def identify_common_size(self, output):
        sizes = re.findall(r'Size: (\d+)', output)
        if not sizes:
            return None

        size_counts = Counter(sizes)
        most_common_size, _ = size_counts.most_common(1)[0]

        return int(most_common_size)

    def extract_domain_from_rustscan(self, rustscan_output):
        match = re.search(r'http-title: .* to (http[s]?://([^/]+))', rustscan_output)
        if match:
            domain = match.group(2)
            print(f"[+] Extracted domain: {domain}")
            return domain
        print("[-] No domain found in RustScan output.")
        return None

    def update_etc_hosts(self, ip, domain):
        hosts_entry = f"{ip}\t{domain}\n"
        try:
            with open("/etc/hosts", 'a') as hosts_file:
                hosts_file.write(hosts_entry)
                print(f"[+] Added {domain} with IP {ip} to /etc/hosts.")
        except Exception as e:
            print(f"[-] Failed to update /etc/hosts: {e}")

    @staticmethod
    def locate_ffuf_directory_wordlist():
        command = ['locate', 'directory-list-2.3-small.txt']
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.stdout:
                wordlist_path = result.stdout.strip().split('\n')[0]
                print(f'[+] Found wordlist at: {wordlist_path}')
                return wordlist_path
            else:
                print('[-] No wordlist found')
        except Exception as e:
            print(f"An error occurred while locating the wordlist: {e}")
            return None


def loading_animation():
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    for _ in range(30):  # Adjust the range for a longer or shorter loading effect
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        time.sleep(0.08)
        sys.stdout.write('\b')


def display_cool_screen():
    # ASCII Art for the tool
    art = """
    

░▒▓███████▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                      
                                                                                      
  """
    print(art)
    print("Loading...")

    # Run the loading animation
    loading_animation()
    print("\nReady to start!\n")


def main():
    display_cool_screen()

    # Get the IP address from the user
    ip = input("Please enter the IP address to scan: ")

    # Create a Scanner instance
    scanner = Scanner(ip)

    # Run RustScan and get the domain if available
    rust_port_scan, domain = scanner.rust_scan()

    # Run Nmap scan on the host
    nmap_port_scan = scanner.nmap_scan()

    # Locate the wordlist for FFUF scan
    wordlist_path = Scanner.locate_ffuf_directory_wordlist()

    # Use the domain for FFUF if available; otherwise, fall back to using the IP
    target_for_ffuf = domain if domain else ip

    if rust_port_scan and wordlist_path and (f'Open {ip}:80' in rust_port_scan or f'Open {ip}:443' in rust_port_scan):
        scanner.ffuf_directory_scan(target_for_ffuf, wordlist_path)
    else:
        print("Skipping FFUF scan as port 80 or 443 is not open, or wordlist not found.")


if __name__ == "__main__":
    main()
