from utilities import *

Narrator_nodes = "../ServerEnclave/host/network/_peer_ip_allowed"
Narrator_Peers = "../ServerEnclave/host/network/_peers"
# Load peers nodes ip
def load_node_ips():
    node = open(Narrator_nodes, "r")
    node_ips = []
    for item in node.readlines():
        node_ips.append(item.strip())
    node.close()
    print(node_ips)
    return node_ips

def load_peer():
    peer_info = dict()
    peer = open(Narrator_Peers, "r")
    peer_ips = []
    for item in peer.readlines():
        peer_ips.append(item.strip())
    peer.close()
    index = 0
    for item in peer_ips:
        # (ip,port,number,role) = item.split(":")
        peer_info[index] = item.split(":")
        index += 1
    print(peer_info)    
    return peer_info

class CommonNarratorClass():
    def __init__(self):
        self.node =load_node_ips()
        self.narrator_core_path = "../ServerEnclave/"
    # TODO Add the init env
    def network_init_narrator_env(self):
        node = self.node

    def network_sync_narrator_core(self):
        node = self.node
        logger.info("Clean the Narrator build folder")
        cmd = ["rm", self.narrator_core_path + "build","-rf"]
        sh(cmd)
        # TODO Add sync the narrator core



test = CommonNarratorClass()
test.network_sync_narrator_core()




# load_peer()
# load_node_ips()










