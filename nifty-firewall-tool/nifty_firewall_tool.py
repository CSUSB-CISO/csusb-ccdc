import subprocess
import json
import re
from flask import Flask, request, jsonify, Response
from functools import wraps


with open('config.json', 'r') as config_file:
    config = json.load(config_file)
API_TOKEN = config['api_key']
file_path = config['idk_how_to_make_an_api']['file_path']
da_lemon = config['idk_how_to_make_an_api']['da_lemon']

app = Flask(__name__)



def update_nft_whitelist(whitelist, wata):
    new_rules  = set()
    new_rules.add(f'ip saddr {whitelist["ip"]} tcp dport {whitelist["port"]};')

    with open(file_path, 'r') as file:
        nftables_content = file.readlines()

    for i, line in enumerate(nftables_content):
        if "chain input {" in line:
            input_chain_start = i

    indentation = 16
    new_rules_with_indentation = [f"{' ' * indentation}{rule}\n" for rule in new_rules]
    nftables_content[input_chain_start + 1:input_chain_start + 1] = new_rules_with_indentation

    with open(file_path, 'w') as file:
            file.writelines(nftables_content)

def update_nft_input(rules, data):
    with open(file_path, 'r') as file:
        nftables_content = file.readlines()

    input_chain_start = None
    input_chain_end = None
    for i, line in enumerate(nftables_content):
        if "chain input {" in line:
            input_chain_start = i
        elif 'type filter hook input priority 0;' in line:
            input_chain_end = i
            break

    if input_chain_start is None or input_chain_end is None:
        raise Exception("Input chain not found or improperly formatted in nftables configuration")

    new_rules = {str(rule_drop): f'tcp dport {rule_drop} drop;' for rule_drop in rules['drop']}
    new_rules.update({str(rule_accept): f'tcp dport {rule_accept} accept;' for rule_accept in rules['accept']})

    updated_content = []
    for line in nftables_content[input_chain_start + 1:input_chain_end]:
        line_stripped = line.strip()
        if line_stripped.startswith('tcp dport') and line_stripped.endswith(('accept;', 'drop;')):
            port = line_stripped.split(' ')[2]
            if port in new_rules:
                updated_content.append(f"{' ' * 16}{new_rules[port]}\n")
                new_rules.pop(port)
            else:
                updated_content.append(line)
        else:
            updated_content.append(line)

    for rule in new_rules.values():
        updated_content.append(f"{' ' * 16}{rule}\n")

    nftables_content[input_chain_start + 1:input_chain_end] = updated_content

    with open(file_path, 'w') as file:
        file.writelines(nftables_content)

    try:
        subprocess.run(["nft", "-f", file_path], check=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"Error running nft command: {e}")

def update_nft_output(rules, data):
    with open(file_path, 'r') as file:
        nftables_content = file.readlines()

    input_chain_start = None
    input_chain_end = None
    for i, line in enumerate(nftables_content):
        if "chain output {" in line:
            input_chain_start = i
        elif 'type filter hook output priority 0;' in line:
            input_chain_end = i
            break

    if input_chain_start is None or input_chain_end is None:
        raise Exception("Output chain not found or improperly formatted in nftables configuration")

    new_rules = {str(rule_drop): f'tcp dport {rule_drop} drop;' for rule_drop in rules['drop']}
    new_rules.update({str(rule_accept): f'tcp dport {rule_accept} accept;' for rule_accept in rules['accept']})

    updated_content = []
    for line in nftables_content[input_chain_start + 1:input_chain_end]:
        line_stripped = line.strip()
        if line_stripped.startswith('tcp dport') and line_stripped.endswith(('accept;', 'drop;')):
            port = line_stripped.split(' ')[2]
            if port in new_rules:
                updated_content.append(f"{' ' * 16}{new_rules[port]}\n")
                new_rules.pop(port)
            else:
                updated_content.append(line)
        else:
            updated_content.append(line)

    for rule in new_rules.values():
        updated_content.append(f"{' ' * 16}{rule}\n")

    nftables_content[input_chain_start + 1:input_chain_end] = updated_content

    with open(file_path, 'w') as file:
        file.writelines(nftables_content)

    try:
        subprocess.run(["nft", "-f", file_path], check=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"Error running nft command: {e}")




def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('API-Token')
        if not token or token != API_TOKEN:
            response_message = da_lemon
            return Response(response_message, status=403, content_type='text/plain')
        return f(*args, **kwargs)
    return decorated_function



@app.route('/api/easteregg', methods=['GET'])
def get_data():
    ascii_art2 = """
⢵⣺⣿⣻⣿⣷⢻⣿⣿⡽⣿⣿⣮⣻⢿⣿⡷⣟⣿⣿⣿⣷⣽⣻⣿⣿⣵⣪⣟⣿
⠉⣼⣿⣷⣝⢿⣿⣿⣷⣽⣮⡻⣾⣿⣿⣿⣿⣾⣿⢿⣿⣷⣿⣷⣽⡝⢿⣿⣿⣿
⣾⣿⣿⣿⣼⣷⣬⣙⠻⢿⣿⣷⣮⡻⣿⣿⣻⢿⣿⣿⡿⣿⣿⣿⣝⢯⡀⢹⣿⣿
⣿⣿⣷⢿⣹⣿⣿⣿⣿⣶⣾⣿⣿⣿⣿⣿⣮⣳⢯⣷⣝⢿⣿⣿⣿⣯⡻⣶⣿⣿
⣟⣿⣿⣏⢿⣿⡟⢻⣿⣿⣻⣿⣿⣿⣿⡻⢿⣻⣿⣿⣿⣿⣿⣿⣿⣿⣷⡽⣿⣿
⣿⣿⣿⣿⣎⣿⣿⠖⣿⣿⣿⣿⣿⣟⢿⣿⡇⢻⣿⠇⢘⠻⣿⣿⣻⣿⣿⣿⣽⣿
⣿⡿⣿⣿⣷⣾⣿⣄⠛⠃⡛⢍⠛⢿⣧⠁⠑⠢⢤⠴⠋⠀⣿⣿⣿⣿⣿⣿⣿⣿
⣿⢆⢻⣿⣿⡞⣿⣏⠛⠛⠁⡘⠀⠀⠈⠑⠀⠀⠀⠀⠀⠀⢸⢹⣿⣿⣿⣿⣞⣿
⣿⢇⡘⡏⢻⢻⣿⣿⠀⠀⠰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠘⣿⣿⣿⢿⣿⣿
⣿⠡⠬⠙⡈⣇⢻⣿⣇⠀⠀⠈⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⢻⡇⠻⡄⠙⢿
⢺⣷⠁⠃⠑⠙⠿⣿⢿⣧⡀⠀⠀⣤⠤⠄⠀⠀⠀⠀⠀⢀⣼⠃⢸⡇⠀⠁⠀⠸
⣸⠇⠀⠀⠀⠀⠀⢹⠘⣿⠘⣦⡀⠀⢌⠨⠀⠀⠀⠀⣰⣿⡏⠀⠈⠇⠀⠀⠀⠀
⠞⢄⠀⠀⠀⠀⠀⠀⠃⠘⡇⠈⠹⣦⡀⠀⠀⢀⡤⢺⢿⣿⠀⠀⠀⠀⠀⠀⠀⢀
⢂⡀⢀⠀⠀⠁⠀⠀⠀⠀⠐⠀⠀⠘⡈⠑⠚⠁⠀⠀⢹⡙⢦⡀⠀⠀⠀⠀⠆⢸
⠀⠀⠀⡀⡎⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠿⡇⠀⢙⣷⠄⠀⢀⠀⠸
"""
    return Response(ascii_art2, content_type='text/plain')



@app.route('/here/are/my/rules/sire', methods=['GET'])
@token_required
def get_active_rules():
    try:
        with open(file_path, "r") as file:
            nftables_content = file.readlines()

        # Initialize a list to store the extracted rules
        rules = []

        # Regular expression pattern to match rule lines
        rule_pattern = r'^\s*(?P<protocol>tcp|udp)\s+dport\s+(?P<dport>\d+)\s+(?P<action>accept|drop);'

        for line in nftables_content:
            line = line.strip()
            match = re.match(rule_pattern, line)
            if match:
                rule_data = match.groupdict()
                rules.append(rule_data)

        response_data = {"rules": rules}
        return jsonify(response_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/welcome/to/the/allowlist', methods=['PUT'])
@token_required
def whitelist_ip_with_port():
    whitelist = {
        "ip": '',
        "port": ''
    }
    try:
        wata = request.get_json()
        for key_ip_port, value_ip_port in wata.items():
            if key_ip_port in whitelist:
                whitelist[key_ip_port] = value_ip_port
            else:
                print(f"nah bruh im ignoring {key_ip_port}")
        update_nft_whitelist(whitelist, wata)
        return jsonify({'message': 'Whitelisting successful'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route ('/hippity/hoppity/your/packets/are/my/property', methods=['PUT'])
@token_required
def update_nf_rules():
        
    rules = {
        "drop": [],
        "accept": []
    }
    try:
        # Get the JSON data from the request
        data = request.get_json()

        # Update the rules dictionary based on the received data
        for action, ports in data.items():
            if action in rules:
                rules[action] = ports

        # Update the nftables.conf file with the new rules
        update_nft_input(rules, data)

        return jsonify({'message': 'Rules updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route ('/the/rules/didnt/work', methods=['PUT'])
@token_required
def flush_nf_rules():
    try:
        subprocess.run(["cp", "freshnftables.conf", "nftables.conf"], check=True)
        subprocess.run(["nft", "-f", "nftables.conf"], check=True)
    except subprocess.CalledProcessError as e:
        return jsonify({'error': str(e)}), 500
    
    return jsonify({'message': 'Rules flushed successfully'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, ssl_context=('/KeyboardKowboys/cert.pem', '/KeyboardKowboys/key.pem'))

