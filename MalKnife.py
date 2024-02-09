import hashlib
import requests
import sys

#Function for calculating the MD5 hash of a file
def calculate_md5_hash(filepath):
    """Calculate the MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

#Checking on Virus Total
def check_virustotal(api_key, resource, resource_type='file'):
    """Check the file or IP reputation via VirusTotal API."""
    if resource_type == 'file':
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
    elif resource_type == 'ip':
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    else:  # for hash, it's the same as for file
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        
    params = {'apikey': api_key, 'resource': resource}
    response = requests.get(url, params=params)
    
    if response.status_code == 200:
        result = response.json()
        if result.get('response_code') == 1:
            if resource_type == 'file' or resource_type == 'hash':
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                print(f"Detection ratio: {positives}/{total}")
            elif resource_type == 'ip':
                print(f"IP report: {result}")
        else:
            print("No information available for this resource.")
    else:
        print("Error querying VirusTotal API")

def main_menu():
    api_key = input("Please enter your VirusTotal API key: ")
    while True:
        print("\nOptions:")
        print("1. Check file")
        print("2. Check IP")
        print("3. Check hash")
        print("4. Exit")
        choice = input("Enter your choice (1/2/3/4): ")

        if choice == '1':
            file_path = input("Enter the absolute path of the file: ")
            md5_hash = calculate_md5_hash(file_path)
            print(f"MD5 Hash: {md5_hash}")
            check_virustotal(api_key, md5_hash, 'file')
        elif choice == '2':
            ip_address = input("Enter the IP address: ")
            check_virustotal(api_key, ip_address, 'ip')
        elif choice == '3':
            hash_input = input("Enter the hash: ")
            check_virustotal(api_key, hash_input, 'hash')
        elif choice == '4':
            print("Exiting.")
            break
        else:
            print("Invalid option. Please try again.")

        if choice in ['1', '2', '3']:
            repeat = input("Do you want to perform another check? (yes/no): ")
            if repeat.lower() != 'yes':
                continue  # This will take the user back to the main menu

if __name__ == "__main__":
    main_menu()

#Made with love by Hector <3 Happy blue teaming!
