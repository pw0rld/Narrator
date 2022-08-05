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
```
## Usage
Add peers ip into pub_ips.txt.

Then, the master machine will be add its ssh key to other peers.

``` Bash
ssh-keygen -t rsa #genc the ssh key
ssh-copy-id -i /home/niu/.ssh/id_rsa.pub root@10.20.61.124 #copy it to other peers

python3 tmtk.py network deploy # deploy tendermint program
python3 tmtk.py network start  # start tendermint network
python3 tmtk.py network stop  # start tendermint network
python3 tmtk.py network fetch-logs  # sync other peers logs

curl -s '10.20.31.146:26657/broadcast_tx_commit?tx="asatoshi3"' #Commit a tx
curl -s '10.20.31.146:26657/abci_query?data="asatoshi3"'        #Query a tx

```

