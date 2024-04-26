import hashlib
import requests
import os
import json
import whois
import base64

# Calculates the MD5 hash of a given file
def calculate_md5_hash(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# VirusTotal API key handler 
def check_virustotal(api_key, resource, resource_type='file'):
    urls = {
        'file': 'https://www.virustotal.com/vtapi/v2/file/report',
        'ip': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
        'hash': 'https://www.virustotal.com/vtapi/v2/file/report'
    }
    url = urls[resource_type]
    params = {'apikey': api_key, 'resource': resource}
    response = requests.get(url, params=params)
    
    if response.status_code == 200:
        result = response.json()
        if result.get('response_code') == 1:
            if resource_type in ['file', 'hash']:
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                print(f"VirusTotal Detection ratio: {positives}/{total}")
            elif resource_type == 'ip':
                print(f"VirusTotal IP report: {result}")
        else:
            print("No information available for this resource.")
    else:
        print("Error querying VirusTotal API")

# AbuseIPDB check function
def check_ip_abuseipdb(api_key, ip_address):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    decoded_response = json.loads(response.text)
    print("AbuseIPDB Response:")
    print(json.dumps(decoded_response, sort_keys=True, indent=4))

# Gets the API key from user or from file which contains it
def get_api_key(filename, prompt):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            api_key = file.read().strip()
    else:
        api_key = input(prompt)
        with open(filename, 'w') as file:
            file.write(api_key)
    return api_key

# Option for allowing user to change its API key
def change_api_key():
    print("\nWhich API key would you like to change?")
    print("1. VirusTotal API key")
    print("2. AbuseIPDB API key")
    choice = input("Enter your choice (1/2): ")
    if choice == '1':
        new_api_key = input("Enter the new VirusTotal API key: ")
        with open('vt_api_key.txt', 'w') as file:
            file.write(new_api_key)
        print("VirusTotal API key updated successfully.")
    elif choice == '2':
        new_api_key = input("Enter the new AbuseIPDB API key: ")
        with open('abuseipdb_api_key.txt', 'w') as file:
            file.write(new_api_key)
        print("AbuseIPDB API key updated successfully.")

#Whois function
def perform_whois(domain):
    try:
        w = whois.whois(domain)
        print("\nWhois Information:")
        print(json.dumps(w, default=str, indent=4))
    except Exception as e:
        print("Failed to retrieve Whois information:", str(e))

#Base64 Decoder function
def decode_base64(data):
    try:
        # Decode the Base64 data
        base64_bytes = base64.b64decode(data)
        return base64_bytes.decode('utf-8')
    except Exception as e:
        return f"An error occurred: {str(e)}"

# Main menu function
def main_menu():
    vt_api_key = get_api_key('vt_api_key.txt', "Please enter your VirusTotal API key: ")
    abuseipdb_api_key = get_api_key('abuseipdb_api_key.txt', "Please enter your AbuseIPDB API key: ")

    while True:
        print("\nOptions:")
        print("1. Check file")
        print("2. Check IP")
        print("3. Check hash")
        print("4. Change API key")
        print("5. Whois lookup")
        print("6. Decode Base64")
        print("q. Exit")
        choice = input("Enter your choice (1/2/3/4/5/6/q): ")

        if choice == '1':
            file_path = input("Enter the absolute path of the file: ")
            md5_hash = calculate_md5_hash(file_path)
            print(f"MD5 Hash: {md5_hash}")
            check_virustotal(vt_api_key, md5_hash, 'file')
            input("Press enter to return to menu...")
        elif choice == '2':
            ip_address = input("Enter the IP address to check: ")
            print("Checking on VirusTotal...")
            check_virustotal(vt_api_key, ip_address, 'ip')
            input("Press enter to see AbuseIPDB results...")
            print("Checking on AbuseIPDB...")
            check_ip_abuseipdb(abuseipdb_api_key, ip_address)
            input("Press enter to return to menu...")
        elif choice == '3':
            hash_input = input("Enter the hash: ")
            check_virustotal(vt_api_key, hash_input, 'hash')
            print(f"Check it on https://virustotal.com/gui/file/{hash_input}")
            input("Press enter to return to menu...")
        elif choice == '4':
            change_api_key()
            # Re-fetch API keys in case they were changed
            vt_api_key = get_api_key('vt_api_key.txt', "Please enter your VirusTotal API key: ")
            abuseipdb_api_key = get_api_key('abuseipdb_api_key.txt', "Please enter your AbuseIPDB API key: ")
        elif choice == '5':
            domain = input("Enter the domain for Whois lookup: ")
            perform_whois(domain)
            input("Press enter to return to menu...")
        elif choice == '6':
            base64_data = input("Enter the Base64 encoded payload: ")
            decoded_output = decode_base64(base64_data)
            print("Decoded output:", decoded_output)
            input("Press enter to return to menu...")
        elif choice.lower() == 'q':
            print("Exiting.")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main_menu()

# Made with love in 2024 by Hector <3 Happy blue teaming!
