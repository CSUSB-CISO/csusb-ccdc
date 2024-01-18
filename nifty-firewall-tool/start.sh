#!/bin/bash

# Read environment variable
API_KEY=${API_KEY:-default_api_key_value}

# Update config.json with the API_KEY environment variable
jq --arg api_key "$API_KEY" '.api_key = $api_key' /KeyboardKowboys/config.json > /tmp/temp.json && mv /tmp/temp.json /KeyboardKowboys/config.json

# Apply nftables configuration
nft -f nftables.conf

# Start the API
exec python3 nifty_firewall_tool.py
