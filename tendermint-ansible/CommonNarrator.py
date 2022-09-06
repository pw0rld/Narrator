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
    def __init__(self,cfg_file):
        self.node =load_node_ips()
        self.narrator_core_path = "../ServerEnclave/"
        self.cfg = load_test_config(cfg_file)
        self.dest_source = "/home/narrator"
        self.workdir = os.path.join(self.cfg.home, "narrator")
        if not os.path.isdir(self.workdir):
            os.makedirs(self.workdir, mode=0o755, exist_ok=True)
            logger.debug("Created folder: %s", self.workdir)
    # TODO Add the init env
    def network_init_narrator_env(self):
        node = self.node

    def network_sync_narrator_core(self):
        cfg = self.cfg
        node = self.node
        logger.info("Clean the Narrator build folder")
        cmd = ["rm", self.narrator_core_path + "build","-rf"]
        sh(cmd)
        workdir = self.workdir
        # Genc the extra-vars
        extra_vars = {
            "service_name": "narrator",
            "service_user": "root",
            "service_group": "narrator",
            "service_user_shell": "/bin/bash",
            "service_template": "narrator.service.jinja2",
            "src_source": "{0}/../ServerEnclave".format(os.getcwd()),
            "dest_source": self.dest_source,
        }

        # /home/cooper/Desktop/Narrator/finally_ccs/pw/Narrator/ServerEnclave
        inventory = OrderedDict()
        inventory["Narrator"] = []
        i = 0
        peer_info = load_peer()
        for peer in node:
            node_id = "node%d" % i
            port = ""
            for i in peer_info:
                info = peer_info[i]
                if info[0] == peer and info[3] != "client":
                    # port += "," + info[1]
                    port = info[1]
            # port = port[1:]
            print(port)
            inventory["Narrator"].append(
                AnsibleInventoryEntry(
                    alias="%s" % node_id,
                    ansible_host = peer,
                    node_id = node_id,
                    port = port,
                ),
            )
            i += 1

        inventory_file = os.path.join(workdir, "inventory")
        save_ansible_inventory(inventory_file, inventory)
        extra_vars_file = os.path.join(workdir, "extra-vars.yaml")
        save_yaml_config(extra_vars_file, extra_vars)

        logger.info("Deploying Narrator Core")
        sh([
            "ansible-playbook",
            "-i", inventory_file,
            "-e", "@%s" % extra_vars_file,
            os.path.join("ansible","narrator_deploy.yaml"),
        ])
        logger.info("Narrator core successfully deployed")
    def network_deploy_narrator(self,state):
        cfg = self.cfg
        node = self.node
        workdir = self.workdir
        valid_states = {"started", "stopped", "restarted"}
        if state not in valid_states:
            raise Exception("Desired service state must be one of: %s", ",".join(valid_states))
        inventory_file = os.path.join(workdir, "inventory")
        state_verb = "starting" if state in {"started", "restarted"} else "stopping"
        logger.info("%s hosts", state_verb.capitalize())
        sh([
            "ansible-playbook",
            "-i", inventory_file,
            "-e", "state=%s" % state,
            os.path.join("ansible", "narrator-state.yaml"),
        ])
        logger.info("Hosts' state successfully set to \"%s\"", state)


# test = CommonNarratorClass()
# test.network_sync_narrator_core()




# load_peer()
load_node_ips()










