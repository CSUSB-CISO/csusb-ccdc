#!/bin/bash

# Apply nftables configuration
nft -f nftables.conf

# Start the API
exec python3 nifty_firewall_tool.py
