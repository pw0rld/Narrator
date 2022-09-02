from utilities import *

NODE_PUB_IPS_FILE = "./pub_ips.txt"
NODE_PRI_IPS_FILE = "./pri_ips.txt"


def load_key(d, ctx) -> TendermintNodeKey:
    if not isinstance(d, dict):
        raise Exception("Expected key to consist of key/value pairs (%s)" % ctx)
    return TendermintNodeKey(**d)

def load_tendermint_priv_validator_key(path: str) -> TendermintNodePrivValidatorKey:
    with open(path, "rt") as f:
        priv_val_key = json.load(f)
    for field in ["address", "pub_key", "priv_key"]:
        if field not in priv_val_key:
            raise Exception("Missing field \"%s\" in %s" % (field, path))
    cfg = {
        "address": priv_val_key["address"],
        "pub_key": load_key(priv_val_key["pub_key"], "pub_key in %s" % path),
        "priv_key": load_key(priv_val_key["priv_key"], "priv_key in %s" % path),
    }
    return TendermintNodePrivValidatorKey(**cfg)

def tendermint_load_peers(base_path: str, node_count: int, node_ips: list) -> List[TendermintNodeConfig]:
    """Loads the relevant Tendermint node configuration for all nodes in the given base path."""
    logger.info("Loading Tendermint testnet configuration for %d nodes from %s", node_count, base_path)
    result = []
    for i in range(node_count):
        node_id = "node%d" % i
        host_cfg_path = os.path.join(base_path, node_id, "config")
        config_file = os.path.join(host_cfg_path, "config.toml")
        config = load_toml_config(config_file)
        priv_val_key = load_tendermint_priv_validator_key(os.path.join(host_cfg_path, "priv_validator_key.json"))
        node_key = load_tendermint_node_key(os.path.join(host_cfg_path, "node_key.json"))
        result.append(
            TendermintNodeConfig(
                config_path=host_cfg_path,
                config=config,
                priv_validator_key=priv_val_key,
                node_key=node_key,
                peer_id=tendermint_peer_id(
                    node_ips['pub'][i],
                    ed25519_pub_key_to_id(
                        get_ed25519_pub_key(
                            node_key.value,
                            "node with configuration at %s" % config_file,
                        ),
                    ),
                ),
            ),
        )
    return result

def tendermint_generate_config(
    workdir: str,
    validators: int,
    keep_existing: bool,
    node_ips: list,) -> List[TendermintNodeConfig]:
    """Generates the Tendermint network configureation for a testnet."""
    logger.info("Genrating Tendermint configuration for testnet")
    if os.path.isdir(workdir):
        if keep_existing:
            logger.info("Configuration already exists, keeping existing configuration")
            return tendermint_load_peers(workdir, validators)
        
        logger.info("Removing existing configuration directory: %s", workdir)
        shutil.rmtree(workdir)

    # ensure_path_exists(workdir)
    if not os.path.isdir(workdir):
        os.makedirs(workdir, mode=0o755, exist_ok=True)
        logger.debug("Created folder: %s", workdir)
    cmd = [
        "tendermint", "testnet",
        "--v", "%d" % validators,
        "--populate-persistent-peers=false", # we'll handle this ourselves later
        "--o", workdir,
    ]
    sh(cmd)
    return tendermint_load_peers(workdir, validators, node_ips)

def tendermint_finalize_config(cfg: "TestConfig", peers: List[TendermintNodeConfig]):
    genesis_doc = {
        "genesis_time": pytz.utc.localize(datetime.datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "chain_id": cfg.id,
        "validators": [],
        "app_hash": "",
    }

    persistent_peers = unique_peer_ids(peers)

    for pp in persistent_peers:
        logger.info("Get persistent peers: %s", persistent_peers)

    for node_cfg in peers:
        genesis_doc["validators"].append({
            "address": node_cfg.priv_validator_key.address,
            "pub_key": {
                "type": node_cfg.priv_validator_key.pub_key.type,
                "value": node_cfg.priv_validator_key.pub_key.value,
            },
            "name": node_cfg.config["moniker"],
            "power": "10",
        })

    for node_cfg in peers:
        _cfg = deepcopy(node_cfg.config)
        # _cfg['log-level'] = "debug" # debug
        # _cfg['tx-index']["indexer"] = [ "kv",] # debug
        _cfg["p2p"]["persistent-peers"] = ",".join(persistent_peers - {node_cfg.peer_id})
        _cfg["rpc"]["laddr"] = "tcp://0.0.0.0:26657"
        _cfg["instrumentation"]["prometheus"] = True
        _cfg["consensus"]["create-empty-blocks"] = False
        _cfg["consensus"]["peer-gossip-sleep-duration"] = "0ms"
        save_toml_config(os.path.join(node_cfg.config_path, "config.toml"), _cfg)

        node_genesis_file = os.path.join(node_cfg.config_path, "genesis.json")
        with open(node_genesis_file, "wt") as f:
            json.dump(genesis_doc, f, indent=2)

def ansible_deploy_tendermint(
    cfg: TestConfig,
    binary_path: str,
    peers: List[TendermintNodeConfig],):

    workdir = os.path.join(cfg.home, "tendermint")
    print(workdir)
    if not os.path.isdir(workdir):
        raise Exception("Missing working directory: %s", workdir)
    logger.info("Generating Ansible configuration for all nodes")
    extra_vars = {
        "service_name": "tendermint",
        "service_user": "root",
        "service_group": "tendermint",
        "service_user_shell": "/bin/bash",
        "service_state": "started",
        "service_template": "tendermint.service.jinja2",
        "service_desc": "Tendermint",
        "service_exec_cmd": "/usr/local/bin/tendermint node --mode validator --proxy-app=kvstore",
        "src_binary": "{0}/tendermint".format(os.getcwd()),
        "dest_binary": "/usr/local/bin/tendermint",
        "src_config_path": os.path.join(workdir, "config"),
    }

    inventory = OrderedDict()
    inventory["tendermint"] = []
    i = 0
    for peer in peers:
        node_id = "node%d" % i
        inventory["tendermint"].append(
            AnsibleInventoryEntry(
                alias="%s" % node_id,
                ansible_host = peer.peer_id.split("@")[1].split(":")[0],
                node_id = node_id,
            ),
        )
        i += 1


    inventory_file = os.path.join(workdir, "inventory")
    save_ansible_inventory(inventory_file, inventory)
    extra_vars_file = os.path.join(workdir, "extra-vars.yaml")
    save_yaml_config(extra_vars_file, extra_vars)
    
    logger.info("Deploying Tendermint network")
    sh([
        "ansible-playbook",
        "-i", inventory_file,
        "-e", "@%s" % extra_vars_file,
        os.path.join("ansible","deploy.yaml"),
    ])
    logger.info("Tendermint network successfully deployed")

def load_node_ips():
    node_ips = dict()
    pub_f = open(NODE_PUB_IPS_FILE, "r")
    pub_ips = []
    for item in pub_f.readlines():
        pub_ips.append(item.strip())
    pub_f.close()
    pri_f = open(NODE_PRI_IPS_FILE, "r")
    pri_ips = []
    for item in pri_f.readlines():
        pri_ips.append(item.strip())
    node_ips['pub'] = pub_ips
    node_ips['pri'] = pri_ips

    return node_ips

def ansible_set_tendermint_nodes_state(
    workdir: str,
    state: str,):

    """Attmpts to collect all nodes' details from the given refernces list
    and ensure that they are all set to the desired state (Ansible state)."""
    valid_states = {"started", "stopped", "restarted"}
    if state not in valid_states:
        raise Exception("Desired service state must be one of: %s", ",".join(valid_states))
    state_verb = "starting" if state in {"started", "restarted"} else "stopping"

    inventory_file = os.path.join(workdir, "inventory")
    logger.info("%s hosts", state_verb.capitalize())
    sh([
        "ansible-playbook",
        "-i", inventory_file,
        "-e", "state=%s" % state,
        os.path.join("ansible", "tendermint-state.yaml"),
    ])
    logger.info("Hosts' state successfully set to \"%s\"", state)

def ansible_fetch_logs(
    workdir: str,):

    inventory_file = os.path.join(workdir, "inventory")
    sh([
        "ansible-playbook",
        "-i", inventory_file,
        os.path.join("ansible", "fetch-logs.yaml"),
    ])

def load_test_config(filename: str) -> TestConfig:
    """Loads the configuration from the given file. Throws an exception if any
    validation fails. On success, returns the configuration."""

    # resolve the tmtest home folder path
    tmtest_home = os.path.expanduser(TMTEST_HOME)
    # ensure_path_exists(tmtest_home)
    if not os.path.isdir(tmtest_home):
        os.makedirs(tmtest_home, mode=0o755, exist_ok=True)
        logger.debug("Created folder: %s", tmtest_home)
    with open(filename, "rt") as f:
        cfg_dict = yaml.safe_load(f)
    
    if "id" not in cfg_dict:
        raise Exception("Missing required \"id\" parameter in configuration file")

    config_base_path = os.path.dirname(os.path.abspath(filename))
    return TestConfig(
        id=cfg_dict["id"],
        # monitoring=load_monitoring_config(cfg_dict.get("monitoring", dict())),
        # abci=load_abci_configs(cfg_dict.get("abci", dict()), config_base_path),
        # node_groups=load_node_groups_config(cfg_dict.get("node_groups", []), config_base_path, abci_config),
        # load_tests=load_load_tests_config(cfg_dict.get("load_tests", [])),
        home=tmtest_home,
    )

class CommonTendermintClass():
    def __init__(self,cfg_file):
        self.cfg = load_test_config(cfg_file)
        self.keep_existing_tendermint_config = False

    def network_state(self,state: str):
        cfg = self.cfg
        logger.info("Attempting to change state of network component(s): %s", state)
        ansible_set_tendermint_nodes_state(
            os.path.join(cfg.home, "tendermint"),
            state,
        )
        logger.info("Successfully changed state of network component(s): %s", state)
        

    def network_deploy_tendermint(self):
        """Deploys the network according to the given configuration."""
        # test_home = os.path.join(cfg.home, cfg.id)
        cfg = self.cfg
        node_ips = load_node_ips()
        # 1. generate tendermint testnet config
        config_path = os.path.join(cfg.home, "tendermint", "config")
        peers = tendermint_generate_config(
            config_path,
            len(node_ips['pub']),
            self.keep_existing_tendermint_config,
            node_ips,
        )

        tendermint_finalize_config(cfg, peers)

        binary_path = os.path.join(cfg.home, "bin")
        # deploy all nodes configuration and start the network
        ansible_deploy_tendermint(
            cfg,
            binary_path,
            peers,
        )
    def fetch_logs_tendermint(self):
        inventory_file = os.path.join(os.path.join(self.cfg.home, "tendermint"), "inventory")
        sh([
            "ansible-playbook",
            "-i", inventory_file,
            os.path.join("ansible", "fetch-logs.yaml"),
        ])