#!/usr/bin/env python3
"""
Test kit for Tendermint testnet
"""
from CommonTendermint import *
from CommonNarrator import *

def main():
    parser = argparse.ArgumentParser(
        description="Test kit for Tendermint testnet",
    )
    parser.add_argument(
        "-c", "--config", 
        default="./tmtestplan.yaml",
        help="The path to the configuration file to use (default: ./tmtestplan.yaml)"
    )
    parser.add_argument(
        "--fail-on-missing-envvars",
        action="store_true",
        default=False,
        help="Causes the script to fail entirely if an environment variable used in the config file is not set (default behaviour will just insert an empty value)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Increase output verbosity",
    )
    subparsers = parser.add_subparsers(
        required=True,
        dest="command",
        help="The tmtestnet command to execute",
    )

    # tendermint network
    parser_network = subparsers.add_parser(
        "tendermint", 
        help="Network-related functionality",
    )
    subparsers_network = parser_network.add_subparsers(
        required=True,
        dest="subcommand",
        help="The network-related command to execute",
    )

    # tendermint network deploy
    parser_network_deploy = subparsers_network.add_parser(
        "deploy", 
        help="Deploy a tendermint network according to its configuration file",
    )
    parser_network_deploy.add_argument(
        "--keep-existing-tendermint-config",
        action="store_true",
        help="If this flag is specified and configuration is already present for a particular node group, it will not be overwritten/regenerated",
    )

    # tendermint network destroy
    parser_network_destroy = subparsers_network.add_parser(
        "destroy", 
        help="Deploy narrator network according to its configuration file",
    )
    parser_network_destroy.add_argument(
        "--keep-monitoring",
        action="store_true",
        help="If this flag is set, any deployed monitoring services will be preserved, while all other services will be destroyed",
    )

    # tendermint network start
    parser_network_start = subparsers_network.add_parser(
        "start", 
        help="Start one or more node(s) or node group(s)",
    )
    parser_network_start.add_argument(
        "node_or_group_ids",
        metavar="node_or_group_id",
        nargs="*",
        help="Zero or more node or group IDs of network node(s) to start. If this is not supplied, all nodes will be started."
    )
    parser_network_start.add_argument(
        "--no-fail-on-missing",
        default=False,
        action="store_true",
        help="By default, this command fails if a group/node reference has not yet been deployed. Specifying this flag will just skip that group/node instead.",
    )

    # tendermint network stop
    parser_network_stop = subparsers_network.add_parser(
        "stop", 
        help="Stop one or more node(s) or node group(s)",
    )
    parser_network_stop.add_argument(
        "node_or_group_ids",
        metavar="node_or_group_id",
        nargs="*",
        help="Zero or more node or group IDs of network node(s) to stop. If this is not supplied, all nodes will be stopped."
    )
    parser_network_stop.add_argument(
        "--no-fail-on-missing",
        default=False,
        action="store_true",
        help="By default, this command fails if a group/node reference has not yet been deployed. Specifying this flag will just skip that group/node instead.",
    )

    # tendermint network fetch_logs
    parser_network_fetch_logs = subparsers_network.add_parser(
        "fetch_logs",
        help="Fetch the logs for one or more node(s) or node group(s). " +
            "Note that this stops any running service instances on the target " +
            "nodes prior to fetching the logs, and then restarts those instances " +
            "that were running previously.",
    )

    # tendermint network reset
    parser_network_reset = subparsers_network.add_parser(
        "reset",
        help="Reset the entire Tendermint network without redeploying VMs",
    )
    parser_network_reset.add_argument(
        "--truncate-logs",
        action="store_true",
        help="If set, the network reset operation will truncate the Tendermint logs prior to starting Tendermint",
    )

    # tendermint network info
    subparsers_network.add_parser(
        "info",
        help="Show information about a deployed network (e.g. hostnames and node IDs)",
    )

    # narrator network
    parser_narrator = subparsers.add_parser(
        "narrator", 
        help="Network-related functionality",
    )
    parser_narrator_network = parser_narrator.add_subparsers(
        required=True,
        dest="subcommand",
        help="The network-related command to execute",
    )


    # narrator network deploy
    parser_narrator_deploy = parser_narrator_network.add_parser(
        "deploy", 
        help="Deploy narrator network according to its configuration file",
    )
    parser_narrator_deploy.add_argument(
        "--keep-existing-tendermint-config",
        action="store_true",
        help="If this flag is specified and configuration is already present for a particular node group, it will not be overwritten/regenerated",
    )
    # narrator network start
    parser_narrator_start = parser_narrator_network.add_parser(
        "start", 
        help="start narrator network",
    )


    args = parser.parse_args()

    configure_logging(verbose=args.verbose)
    # Allow for interpolation of environment variables within YAML files
    configure_env_var_yaml_loading(fail_on_missing=args.fail_on_missing_envvars)

    kwargs = {
        # "aws_keypair_name": os.environ.get("AWS_KEYPAIR_NAME", getattr(args, "aws_keypair_name", default_aws_keypair_name)),
        # "ec2_private_key_path": os.environ.get("EC2_PRIVATE_KEY", getattr(args, "ec2_private_key", default_ec2_private_key)),
        "keep_existing_tendermint_config": getattr(args, "keep_existing_tendermint_config", False),
        "node_or_group_ids": getattr(args, "node_or_group_ids", []),
        "fail_on_missing": not getattr(args, "no_fail_on_missing", False),
        "load_test_id": getattr(args, "load_test_id", None),
        "keep_monitoring": getattr(args, "keep_monitoring", False),
        "truncate_logs": getattr(args, "truncate_logs", False),
    }
    sys.exit(tmtest(args.config, args.command, args.subcommand, **kwargs))

# -----------------------------------------------------------------------------
#
#   Core functionality
#
# -----------------------------------------------------------------------------

def tmtest(cfg_file, command, subcommand, **kwargs) -> int:
    """The primary programmatic interface to the tm-test tool. Allows the
    tool to be imported from other Python code. Returns the intended exit code
    from execution."""
    try:
        tendermint_class = CommonTendermintClass(cfg_file)
        narrator_class = CommonNarratorClass(cfg_file)
    except Exception as e:
        logger.error("Failed to load configuration from file: %s", cfg_file)
        logger.exception(e)
        return 1

    fn = True
    try:
        if command == "tendermint":
            if subcommand == "deploy":
                tendermint_class.network_deploy_tendermint()
                fn = False
            elif subcommand == "start":
                tendermint_class.network_state("started")
                fn = False
            elif subcommand == "stop":
                tendermint_class.network_state("stopped")
                fn = False
            elif subcommand == "fetch_logs":
                tendermint_class.fetch_logs_tendermint()
                fn = False
            elif subcommand == "info":
                fn = network_info
        elif command == "narrator":
            if subcommand == "deploy":
                fn = narrator_class.network_sync_narrator_core()
                pass
            if subcommand == "start":
                fn = narrator_class.network_deploy_narrator("started")
                pass
            if subcommand == "stop":
                pass
            if subcommand == "fetch_logs":
                pass
        if fn:
            logger.error("Command/sub-command not yet supported: %s %s", command, subcommand)
            return 1
    except Exception as e:
        logger.error("Failed to execute \"%s %s\" for configuration file: %s", command, subcommand, cfg_file)
        logger.exception(e)
        return 1
    return 0

if __name__ == "__main__":
    main()
