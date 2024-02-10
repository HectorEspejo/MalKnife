# MalKnife
A Swiss knife for blue teamers -  I really got tired of having to check everything over and over on the browser
![image](https://github.com/HectorEspejo/MalKnife/assets/5872877/174a705d-afb1-4908-b8d3-a440947414f7)
## What is MalKnife
MalKnife is a Python script perfect for any blue teamers - analyst in SOC, on threat intelligence, on malware analysis. It provides the following options:
- Check a file using an absolute path
- Check an IP
- Check an MD5 hash
<img width="387" alt="image" src="https://github.com/HectorEspejo/MalKnife/assets/5872877/4052eab6-9cd9-4783-b56a-17b09b53de37">

## Requirements
MalKnife needs the following Python libraries:
```
pip install requests
```
```
pip install hashlib
```

Also you will need a VirusTotal API key. For getting one do the following:
- Go to [VirusTotal](https://www.virustotal.com/)
- Create an account / Log in
- Click on your name on the upper, right side of the window
- Click on 'API key'
- Copy it and paste it when the script asks you for it
<img width="1301" alt="image" src="https://github.com/HectorEspejo/MalKnife/assets/5872877/00f3d30c-970f-49bd-9821-ddf7ffc9955f">

## How Do I Make It Work

First, clone this repository on your computer
```
git clone https://github.com/HectorEspejo/MalKnife.git
```

Then just do the usual running method with Python scripts
```
python MalKnife.py
```

## To-Do's

- [ ] Integration with other hash checkers like IBM X-Force, Talos (this will require API keys for each of them too)
- [ ] Add main option to check if IP is from VPN vendor with Spur.us
- [ ] Integration of Whois
- [ ] Give option to check if there are any Any.run sandbox machines for that file
- [ ] Check reputation of website with URLScan.io
- [ ] More
