# masmap_scrpit

a script combine masscan and nmap

## requirements

- masscan 

- nmap

> pip install python-nmap

## usage

> sudo python3 masmap_scrpit.py host \[-r ip.txt] \[-o output_filename]

## how this script scan

this script run 2 concurrent Masscan jobs with all 65535 ports split into 4-5 ranges. Then put the result into the Nmap to detect the version/service of those ports.

reference: [https://captmeelo.com/pentest/2019/07/29/port-scanning.html](https://captmeelo.com/pentest/2019/07/29/port-scanning.html)
