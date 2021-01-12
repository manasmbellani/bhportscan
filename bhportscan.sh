#!/bin/bash
SCRIPT_DIR=$(dirname "$0")
OUT_FOLDER="/opt/dockershare/bhportscan"
OUT_FILE_PREFIX="out-portscan-"
DEFAULT_PROTOCOLS_TO_SCAN="all"
DEFAULT_PORTS_TO_SCAN="top1000"
DEFAULT_UDP_PORTS_TO_SCAN="top25"
DEFAULT_SIGNATURES_FILE="$SCRIPT_DIR/signatures.yaml"
TCP_COMMON_PORTS="22,25,53,80,110,143,443,465,587,995,8080,8443,9080,9443"
UDP_COMMON_PORTS="22,25,53,80,110,143,443,465,587,995,8080,8443,9080,9443"
NMAP_OUT_FILE_PREFIX="out-portscansingle"
UNKNOWN_SERVICE="unknown"
DEFAULT_VERSION_SCAN=0
if [ $# -lt 1 ]; then
    echo "[-] $0 <target> [protocol=all|tcp|udp] 
[tcp-ports=top1000|common|all|<custom-list-eg-22,80,...>]
[udp-ports=top25|common|all|<custom-list-eg-22,80,...>] 
[version_scan=$DEFAULT_VERSION_SCAN] 
[signature_file=$DEFAULT_SIGNATURES_FILE] [out_folder=$OUT_FOLDER]"
    exit 1
fi
target="${1}"
protocols_to_scan=${2:-"$DEFAULT_PROTOCOLS_TO_SCAN"}
ports=${3:-"$DEFAULT_PORTS_TO_SCAN"}
udp_ports=${4:-"$DEFAULT_UDP_PORTS_TO_SCAN"}
version_scan=${5:-"$DEFAULT_VERSION_SCAN"}
signatures_file=${6:-"$DEFAULT_SIGNATURES_FILE"}
out_folder=${7:-"$OUT_FOLDER"}

echo "[*] Create the out folder: $out_folder if it doesn't exist"
[ ! -d "$out_folder" ] && mkdir -p "$out_folder"

echo "[*] Obtaining the TCP ports arg for ports: $ports"
if [ "$ports" == "top1000" ]; then
    ports_arg=" --top-ports 1000"
elif [ "$ports" == "common" ]; then
    ports_arg="$TCP_COMMON_PORTS"
elif [ "$ports" == "all" ]; then
    ports_arg=" -p- "
else
    ports_arg=" -p $ports "
fi
echo "[*] ports_arg: $ports_arg chosen for ports: $ports when TCP scanning target: $target"

echo "[*] Obtaining the UDP ports arg for ports: $ports"
if [ "$udp_ports" == "top25" ]; then
    udp_ports_arg=" --top-ports 25"
elif [ "$udp_ports" == "common" ]; then
    udp_ports_arg="$UDP_COMMON_PORTS"
elif [ "$udp_ports" == "all" ]; then
    udp_ports_arg=" -p- "
else
    udp_ports_arg=" -p $udp_ports"
fi
echo "[*] udp_ports_arg: $udp_ports_arg chosen for ports: $ports when UDP scanning target: $target"

echo "[*] Checking if signatures file: $signatures_file exists"
if [ ! -f "$signatures_file" ]; then
    echo "[-] Signatures file: $signatures_file does not exist"
    exit 1
fi

echo "[*] Checking if TCP version scan must be applied for target: $target"
if [ "$version_scan" == "1" ]; then
    version_scan_arg=" -sV "
else
    version_scan_arg=""
fi
echo "[*] version_scan_arg: $version_scan_arg for input: $version_scan"

if [ "$protocols_to_scan" == "tcp" ] || [ "$protocols_to_scan" == "all" ]; then
    echo "[*] Running TCP port scan on target: $target with spec: $ports via nmap"
    protocol="tcp"
    nmap_cmd="nmap -sS -Pn --stats-every=5s "
    nmap_cmd="$nmap_cmd $version_scan_arg $ports_arg $target"
    out_file_tcp_grep="$out_folder/$NMAP_OUT_FILE_PREFIX-$protocol-$target.grep"
    out_file_tcp_xml="$out_folder/$NMAP_OUT_FILE_PREFIX-$protocol-$target.xml"
    out_file_tcp_txt="$out_folder/$NMAP_OUT_FILE_PREFIX-$protocol-$target.txt"
    out_file_tcp_log="$out_folder/$NMAP_OUT_FILE_PREFIX-$protocol-$target.log"
    nmap_cmd="$nmap_cmd --open -oG $out_file_tcp_grep -oX $out_file_tcp_xml -oN $out_file_tcp_txt 2>&1 1>$out_file_tcp_log"

    echo "[*] Executing TCP scan on target: $target via command: $nmap_cmd"
    /bin/bash -c "$nmap_cmd"
fi

if [ "$protocols_to_scan" == "udp" ] || [ "$protocols_to_scan" == "all" ]; then
    echo "[*] Running UDP port scan on target: $target with spec: $ports via nmap"
    protocol="udp"
    nmap_cmd="nmap -sU -Pn --stats-every=5s "
    nmap_cmd="$nmap_cmd $version_scan_arg $udp_ports_arg $target"
    out_file_udp_grep="$out_folder/$NMAP_OUT_FILE_PREFIX-$protocol-$target.grep"
    out_file_udp_xml="$out_folder/$NMAP_OUT_FILE_PREFIX-$protocol-$target.xml"
    out_file_udp_txt="$out_folder/$NMAP_OUT_FILE_PREFIX-$protocol-$target.txt"
    out_file_udp_log="$out_folder/$NMAP_OUT_FILE_PREFIX-$protocol-$target.log"
    nmap_cmd="$nmap_cmd --open -oG $out_file_udp_grep -oX $out_file_udp_xml -oN $out_file_udp_txt 2>&1 1>$out_file_udp_log"

    echo "[*] Executing UDP scan on target: $target via command: $nmap_cmd"
    /bin/bash -c "$nmap_cmd"
fi

echo "[*] Parsing TCP/UDP output from file: $out_file_tcp_txt,$out_file_udp_txt for open ports"
out_file_open_services="$out_folder/$NMAP_OUT_FILE_PREFIX-open-services-$target.txt"
if [ -f "$out_file_tcp_txt" ]; then
    tcp_open_port_lines=$(cat "$out_file_tcp_txt" | grep -iE "/tcp.*open")
else
    tcp_open_port_lines=""
fi
if [ -f "$udp_open_port_lines" ]; then
    udp_open_port_lines=$(cat "$out_file_udp_txt" | grep -iE "/udp.*open")
else
    udp_open_port_lines=""
fi
open_port_lines=$(echo "$tcp_open_port_lines";echo "$udp_open_port_lines")

echo "[*] Clearing outfile: $out_file_open_services if it already exists"
[ -f "$out_file_open_services" ] && rm "$out_file_open_services"

echo "[*] Parsing open services for TCP/UDP to outfile: $out_file_open_services"
IFS=$'\n'

echo "[*] Getting number of signatures in signatures_file: $signatures_file"
signatures=$(cat "$signatures_file" | yq -r ".signatures")
signatures_list_len=$(echo "$signatures" | yq -r ".|length")

echo "[*] Parsing each TCP, UDP open port line"
for open_port_line in $open_port_lines; do
    port=$(echo "$open_port_line" | grep -iEo "[0-9]+/(tcp|udp)" | cut -d"/" -f1)
    protocol=$(echo "$open_port_line" | grep -iEo "[0-9]+/(tcp|udp)" | cut -d"/" -f2)
    
    signature_found=0
    
    for i in $(seq 0 $(($signatures_list_len-1))); do
        signature=$(echo "$signatures" | yq -r ".[$i]")
        signature_regex=$(echo "$signature" | yq -r ".regex")
        signature_service=$(echo "$signature" | yq -r ".protocol")

        is_matching_service=$(echo "$open_port_line" | grep -iE "$signature_regex")
        if [ ! -z "$is_matching_service" ]; then
            signature_found=1
            break
        fi
    done
    if [ $signature_found -eq 0 ]; then
        signature_service="$UNKNOWN_SERVICE"
    fi
    open_service_out_line="[$protocol] $signature_service://$target:$port"
    echo "$open_service_out_line" >> "$out_file_open_services"
    echo "[+] Found service: $open_service_out_line"
done
