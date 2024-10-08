# Advanced Firewall Application

## Overview
This application is an advanced firewall system built using Python and Tkinter. It allows users to add, edit, and manage firewall rules, including support for ICMP and ANY SERVICE protocols. The application also features packet sniffing capabilities to detect potential intrusions.

## Features
- Add, edit, and delete firewall rules
- Support for various protocols, including HTTP, HTTPS, FTP, SSH, DNS, and more
- Support for ICMP and ANY SERVICE protocols
- Intrusion detection capabilities
- Logging of actions and events
- User-friendly GUI with Tkinter

## Dependencies
This application requires the following Python libraries:
- `tkinter` (for GUI)
- `logging` (for logging events)
- `json` (for saving and loading rules)
- `threading` (for managing packet sniffing in the background)
- `scapy` (for packet sniffing and manipulation)

## To install the required dependencies, run the following commands in your CentOS VM:
sudo yum install python3
pip3 install scapy
sudo yum install python3-pip



## For run the code 
sudo yum install python3-pippython3 your_script_name.py



