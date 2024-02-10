import hashlib
import requests
import os

#Calculates the MD5 hash of a given file
def calculate_md5_hash(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

#Virus Total API key handler 
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
                print(f"Detection ratio: {positives}/{total}")
                input()
            elif resource_type == 'ip':
                print(f"IP report: {result}")
                input()
        else:
            print("No information available for this resource.")
            input()
    else:
        print("Error querying VirusTotal API")
        input()

# Gets the API key from user or from file 'vt_api_key.txt' which contains it
# If the user has not used the script before it will create a file with the key after it is entered
def get_api_key():
    api_key_file = 'vt_api_key.txt'
    if os.path.exists(api_key_file):
        with open(api_key_file, 'r') as file:
            api_key = file.read().strip()
    else:
        api_key = input("Please enter your VirusTotal API key: ")
        with open(api_key_file, 'w') as file:
            file.write(api_key)
    return api_key

# Option for allowing user to change its API key
def change_api_key():
    new_api_key = input("Enter the new VirusTotal API key: ")
    with open('vt_api_key.txt', 'w') as file:
        file.write(new_api_key)
    print("API key updated successfully.")

def main_menu():
    api_key = get_api_key()
    while True:
        print("\nOptions:")
        print("1. Check file")
        print("2. Check IP")
        print("3. Check hash")
        print("4. Change API key")
        print("q. Exit")
        choice = input("Enter your choice (1/2/3/4/q): ")

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
            change_api_key()
            api_key = get_api_key()  # Refresh the API key in case it was changed
        elif choice.lower() == 'q':
            print("Exiting.")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main_menu()

#Made with love by Hector <3 Happy blue teaming!
