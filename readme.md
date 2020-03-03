# masmap_scrpit

a script combine masscan and nmap

## requirements

- masscan 

- nmap

> pip install python-nmap

## usage

```
usage: masmap_scpript.py [-h] [-r INPUT] [-c CIDR] [-o OUTPUT] [host]

positional arguments:
  host                  read ip from a file

optional arguments:
  -h, --help            show this help message and exit
  -r INPUT, --input INPUT
                        read ip from a file
  -c CIDR, --cidr CIDR  scan a range of ip
  -o OUTPUT, --output OUTPUT
                        output filename
```
## how this script scan

this script run 2 concurrent Masscan jobs with all 65535 ports split into 4-5 ranges. Then put the result into the Nmap to detect the version/service of those ports.

reference: [https://captmeelo.com/pentest/2019/07/29/port-scanning.html](https://captmeelo.com/pentest/2019/07/29/port-scanning.html)
