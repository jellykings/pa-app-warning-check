# pa-app-warning-check

This script fetches security rules from a Palo Alto firewall, stores them in a dictionary, and checks for policy warnings. It uses the Palo Alto API to retrieve the rules and check for any required actions based on the rule UUIDs.

## Features

- Fetch security rules from a Palo Alto firewall
- Store rules in a dictionary with rule names as keys and UUIDs as values
- Check for policy warnings for each rule
- Print action required messages by default
- Optionally print "no action required" messages with the `-v` flag

## Requirements

- Python 3.x
- `requests` library

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/palo-app-check.git
    cd palo-app-check
    ```

2. Install the required Python packages:
    ```sh
    pip install requests
    ```

## Usage

Run the script with the following command:
```sh
python main.py
```

## Command-line Options

`-v`, `--verbose`: Enable verbose mode to print the rules dictionary and "no action required" messages.

### Example
```sh
python main.py -v
```
