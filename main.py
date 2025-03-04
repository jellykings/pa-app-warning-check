import requests
import base64
import getpass
import xml.etree.ElementTree as ET
import argparse

def get_credentials():
    firewall_ip = input("Enter the firewall IP: ")
    port = input("Enter the port (default 443): ") or "443"
    username = input("Enter the username (default admin): ") or "admin"
    password = getpass.getpass("Enter the password: ")
    return firewall_ip, port, username, password

def get_security_rules(firewall_ip, port, auth_header):
    url = f"https://{firewall_ip}:{port}/api/?type=config&action=get&xpath=/config/devices/entry/vsys/entry/rulebase/security/rules"
    headers = {
        'Authorization': f'Basic {auth_header}'
    }
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        try:
            return ET.fromstring(response.content)
        except ET.ParseError:
            print("Error: Response content is not valid XML")
            print(response.text)
            response.raise_for_status()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        response.raise_for_status()

def store_rules_in_dict(rules):
    rules_dict = {}
    for rule in rules.findall(".//entry"):
        rule_name = rule.get('name')
        rule_uuid = rule.get('uuid')
        if rule_uuid is not None:
            rules_dict[rule_name] = rule_uuid
        else:
            print(f"Warning: 'uuid' attribute not found for rule '{rule_name}'")
    return rules_dict

def check_policy_warnings(firewall_ip, port, auth_header, rules_dict, verbose):
    for rule_name, rule_uuid in rules_dict.items():
        url = f"https://{firewall_ip}:{port}/api/?type=op&cmd=<show><app-warning><warning-message><uuid>{rule_uuid}</uuid><vsys>vsys1</vsys></warning-message></app-warning></show>"
        headers = {
            'Authorization': f'Basic {auth_header}'
        }
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            try:
                result = ET.fromstring(response.content)
                warning_msg = result.find(".//warning-msg")
                if warning_msg is not None:
                    warning_text = warning_msg.find(".//member").text if warning_msg.find(".//member") is not None else warning_msg.text
                    if warning_text:
                        print(f"Action required for rule '{rule_name}': {warning_text}")
                    elif verbose:
                        print(f"No action required for rule '{rule_name}'")
                elif verbose:
                    print(f"No action required for rule '{rule_name}'")
            except ET.ParseError:
                print(f"Error: Response content is not valid XML for rule '{rule_name}'")
                print(response.text)
        else:
            print(f"Error: {response.status_code} - {response.text} for rule '{rule_name}'")

def main():
    parser = argparse.ArgumentParser(description="Palo Alto Firewall Security Rules Fetcher")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose mode to print rules dictionary and 'no action required' messages")
    args = parser.parse_args()

    firewall_ip, port, username, password = get_credentials()
    auth_header = base64.b64encode(f"{username}:{password}".encode()).decode()
    rules = get_security_rules(firewall_ip, port, auth_header)
    rules_dict = store_rules_in_dict(rules)
    print("Security rules have been stored in the dictionary.")

    if args.verbose:
        print("Rules Dictionary:")
        for rule_name, rule_uuid in rules_dict.items():
            print(f"{rule_name}: {rule_uuid}")

    check_policy_warnings(firewall_ip, port, auth_header, rules_dict, args.verbose)

if __name__ == "__main__":
    main()
