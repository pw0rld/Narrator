# tm-testkit
An automatic deployment tool for tendermint.

## Installation
It's recommended that you use a Python3.8 virtual environment to manage
dependencies for the `tm-testkit` tool.

```bash
# Create the virtual environment in a folder called "venv"
sudo apt install python3.8-venv
python3 -m venv venv

# Activate your Python virtual environment
source venv/bin/activate

# Install dependencies for tmtestnet (this will install Ansible, amongst other
# dependencies, into your virtual environment)
pip3 install -r requirements.txt