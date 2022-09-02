import argparse
import os
import os.path
import string
import sys
import re
import logging
import subprocess
import shlex
import time
import hashlib
from typing import OrderedDict as OrderedDictType, List, Dict, Set
from collections import namedtuple, OrderedDict
from copy import copy, deepcopy
import zipfile
import shutil
import pwd
import json
import datetime
import base64
import tempfile

import yaml
import colorlog
import requests
import toml
import pytz

# -----------------------------------------------------------------------------
#
#   Constants
#
# -----------------------------------------------------------------------------

logger = logging.getLogger("")

ENV_VAR_MATCHERS = [
    re.compile(r"\$\{(?P<env_var_name>[^}^{]+)\}"),
    re.compile(r"\$(?P<env_var_name>[A-Za-z0-9_]+)"),
]

TMTEST_HOME = os.environ.get("TMTEST_HOME", "~/.tmtestkit")


# -----------------------------------------------------------------------------
#
#   Configuration
#
# -----------------------------------------------------------------------------

TestConfig = namedtuple("TestConfig",
    ["id", "bin","monitoring", "validators", "abci", "load_tests", "home", "tendermint_binaries"],
    defaults=[None, None, None, dict(), dict(), OrderedDict(), TMTEST_HOME, dict()],
)


TestNodeRef = namedtuple("TestNodeRef",
    ["id"],
    defaults=[None],
)

TendermintNodeConfig = namedtuple("TendermintNodeConfig",
    ["config_path", "config", "priv_validator_key", "node_key", "peer_id"],
)

TendermintNodePrivValidatorKey = namedtuple("TendermintNodePrivValidatorKey",
    ["address", "pub_key", "priv_key"],
)

TendermintNodeKey = namedtuple("TendermintNodeKey", 
    ["type", "value"],
)

AnsibleInventoryEntry = namedtuple("AnsibleInventoryEntry",
    ["alias", "ansible_host", "node_id"],
    defaults=[None, None, None],
)

def configure_env_var_yaml_loading(fail_on_missing=False):
    for matcher in ENV_VAR_MATCHERS:
        yaml.add_implicit_resolver("!envvar", matcher, None, yaml.SafeLoader)
    yaml.add_constructor("!envvar", make_envvar_constructor(fail_on_missing=fail_on_missing), yaml.SafeLoader)

def make_envvar_constructor(fail_on_missing=False):
    def envvar_constructor(loader, node):
        """From https://stackoverflow.com/a/52412796/1156132"""
        value = node.value
        for matcher in ENV_VAR_MATCHERS:
            match = matcher.match(value)
            if match is not None:
                env_var_name = match.group("env_var_name")
                logger.debug("Parsed environment variable: %s", env_var_name)
                if fail_on_missing and env_var_name not in os.environ:
                    raise Exception("Missing environment variable during configuration file parsing: %s" % env_var_name)
                return os.environ.get(env_var_name, "") + value[match.end():]
        raise Exception("Internal error: environment variable matching algorithm failed")
    return envvar_constructor

# -----------------------------------------------------------------------------
#
#   Utilities
#
# -----------------------------------------------------------------------------


def sh(cmd):
    logger.info("Executing command: %s" % " ".join(cmd))
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as p:
        print("")
        for line in p.stdout:
            print(line.decode("utf-8").rstrip())
        while p.poll() is None:
            time.sleep(1)
        print("")
    
        if p.returncode != 0:
            raise Exception("Process failed with return code %d" % p.returncode)

def configure_logging(verbose=False):
    """Supercharge our logger."""
    handler = colorlog.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s\t%(levelname)s\t%(message)s",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "bold_yellow",
                "ERROR": "bold_red",
                "CRITICAL": "bold_red",
            }
        ),
    )
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

def save_toml_config(filename, cfg):
    with open(filename, "wt") as f:
        toml.dump(cfg, f)
    logger.debug("Wrote configuration to %s", filename)

def save_yaml_config(filename, cfg):
    with open(filename, "wt") as f:
        yaml.safe_dump(cfg, f)
    logger.debug("Wrote configuration to %s", filename)

def save_ansible_inventory(filename: str, inventory: OrderedDictType[str, List]):
    """Writes the given inventory structure to an Ansible inventory file.
    The `inventory` variable is an ordered mapping of group names to lists of
    hostnames (plain strings) or AnsibleInventoryEntry instances.

    If you use any AnsibleInventoryEntry instances in your inventory lists, the
    `alias` property is required.
    """
    with open(filename, "wt") as f:
        for group_name, entries in inventory.items():
            f.write("[%s]\n" % group_name)
            for entry in entries:
                if isinstance(entry, str):
                    f.write("%s\n" % entry)
                elif isinstance(entry, AnsibleInventoryEntry):
                    if entry.alias is None:
                        raise Exception("Missing alias for Ansible inventory entry in group: %s" % group_name)
                    line = "%s" % entry.alias
                    if entry.ansible_host is not None:
                        line += " ansible_host=%s" % entry.ansible_host
                    if entry.node_id is not None:
                        line += " node_id=%s" % entry.node_id
                    line += " ansible_ssh_user=root"
                    f.write("%s\n" % line)
                else:
                    raise Exception("Unknown type for Ansible inventory entry: %s" % entry)
                    
            f.write("\n")

def load_toml_config(filename):
    logger.debug("Loading TOML configuration file: %s", filename)
    with open(filename, "rt") as f:
        return toml.load(f)

def load_tendermint_node_key(filename: str) -> TendermintNodeKey:
    """Loads the node's private key from the given file."""
    with open(filename, "rt") as f:
        node_key = json.load(f)
    if "priv_key" not in node_key:
        raise Exception("Invalid node key format in file: %s" % filename)
    if node_key["priv_key"].get("type", "") != "tendermint/PrivKeyEd25519":
        raise Exception("The only node key type currently supported is tendermint/PrivKeyEd25519: %s" % filename)
    return TendermintNodeKey(**node_key["priv_key"])

def get_ed25519_pub_key(priv_key: str, ctx: str) -> bytes:
    """Returns the public key associated with the given private key. Assumes
    that the priv_key is provided in base64, and the latter half of the private
    key is the public key."""
    priv_key_bytes = base64.b64decode(priv_key)
    if len(priv_key_bytes) != 64:
        raise Exception("Invalid ed25519 private key: %s (%s)" % (priv_key, ctx))
    pub_key_bytes = priv_key_bytes[32:]
    if sum(pub_key_bytes) == 0:
        raise Exception("Public key bytes in ed25519 private key not initialized: %s (%s)" % (priv_key, ctx))
    return pub_key_bytes

def resolve_relative_path(path: str, base_path: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(base_path, path))

def tendermint_peer_id(host: str, address: str = None) -> str:
    return ("%s@%s:26656" % (address, host)) if address is not None else ("%s:26656" % host)

def ed25519_pub_key_to_id(pub_key: bytes) -> str:
    """Converts the given ed25519 public key into a Tendermint-compatible ID."""
    sum_truncated = hashlib.sha256(pub_key).digest()[:20]
    return "".join(["%.2x" % b for b in sum_truncated])

def unique_peer_ids(
    peers: List[TendermintNodeConfig],) -> Set[str]:
    result = set()
    for peer in peers:
        result.add(peer.peer_id)
    return result
