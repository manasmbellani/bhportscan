#!/bin/bash
if [ $# -lt 1 ]; then
    echo "[-] $0 <ip-range>"
    exit 1
fi
ip_range="$1"
nmap -sL -n "$ip_range" | grep -i "Nmap Scan Report" | cut -d" " -f5
