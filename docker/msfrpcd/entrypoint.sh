#!/bin/bash
set -e

MSF_RPC_USER=${MSF_RPC_USER:-msf}
MSF_RPC_PASS=${MSF_RPC_PASS:-changeme}

echo "[*] Starting Metasploit RPC daemon..."
/usr/src/metasploit-framework/msfrpcd -U "$MSF_RPC_USER" -P "$MSF_RPC_PASS" -a 0.0.0.0 -p 55553 -S -f
