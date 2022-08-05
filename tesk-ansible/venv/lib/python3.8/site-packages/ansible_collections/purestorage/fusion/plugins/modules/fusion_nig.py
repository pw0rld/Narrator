#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_nig
version_added: '1.0.0'
short_description:  Manage Network Interface Groups in Pure Storage Fusion
description:
- Create, delete and modify network interface groups in Pure Storage Fusion.
- Currently this only supports a single tenant subnet per tenant network
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the network interface group.
    type: str
    required: true
  display_name:
    description:
    - The human name of the network interface group.
    - If not provided, defaults to C(name)
    type: str
  state:
    description:
    - Define whether the network interface group should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  availability_zone:
    aliases: [ az ]
    description:
    - The name of the availability zone for the network interface group.
    type: str
    required: true
  region:
    description:
    - Region for the network interface group
    type: str
    required: true
  gateway:
    description:
    - Address of the subnet gateway
    type: str
  mtu:
    description:
    - MTYU setting for the subnet
    default: 1500
    type: int
  group_type:
    description:
    - The type of network interface group
    type: str
    default: eth
    choices: [ eth ]
  prefix:
    description:
    - Network prefix in CIDR format
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new network interface group foo in AZ bar
  purestorage.fusion.fusion_nig:
    name: foo
    availability_zone: bar
    region: region1
    mtu: 9000
    gateway: 10.21.200.1
    prefix: 10.21.200.0/24
    state: present
    app_id: key_name
    key_file: "az-admin-private-key.pem"

- name: Delete network interface group foo in AZ bar
  purestorage.fusion.fusion_nig:
    name: foo
    availability_zone: bar
    region: region1
    state: absent
    app_id: key_name
    key_file: "az-admin-private-key.pem"
"""

RETURN = r"""
"""


HAS_FUSION = True
try:
    import fusion as purefusion
except ImportError:
    HAS_FUSION = False

try:
    from netaddr import IPNetwork

    HAS_NETADDR = True
except ImportError:
    HAS_NETADDR = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    get_fusion,
    fusion_argument_spec,
)


def get_nig(module, fusion):
    """Check Network Interface Group"""
    nig_api_instance = purefusion.NetworkInterfaceGroupsApi(fusion)
    try:
        return nig_api_instance.get_network_interface_group(
            availability_zone_name=module.params["availability_zone"],
            region_name=module.params["region"],
            network_interface_group_name=module.params["name"],
        )
    except purefusion.rest.ApiException:
        return None


def get_az(module, fusion):
    """Availability Zone or None"""
    az_api_instance = purefusion.AvailabilityZonesApi(fusion)
    try:
        return az_api_instance.get_availability_zone(
            availability_zone_name=module.params["availability_zone"],
            region_name=module.params["region"],
        )
    except purefusion.rest.ApiException:
        return None


def create_nig(module, fusion):
    """Create Network Interface Group"""

    nig_api_instance = purefusion.NetworkInterfaceGroupsApi(fusion)

    changed = True
    if module.params["gateway"] and module.params["gateway"] not in IPNetwork(
        module.params["prefix"]
    ):
        module.fail_json(msg="Gateway and subnet prefix are not compatible.")

    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        try:
            if module.params["group_type"] == "eth":
                if module.params["gateway"]:
                    eth = purefusion.NetworkInterfaceGroupEthPost(
                        prefix=module.params["prefix"],
                        gateway=module.params["gateway"],
                        mtu=module.params["mtu"],
                    )
                else:
                    eth = purefusion.NetworkInterfaceGroupEthPost(
                        prefix=module.params["prefix"],
                        mtu=module.params["mtu"],
                    )
                nig = purefusion.NetworkInterfaceGroupPost(
                    group_type="eth",
                    eth=eth,
                    name=module.params["name"],
                    display_name=display_name,
                )
            nig_api_instance.create_network_interface_group(
                nig,
                availability_zone_name=module.params["availability_zone"],
                region_name=module.params["region"],
            )
        except purefusion.rest.ApiException as err:
            module.fail_json(
                msg="Network Interface Group {0} creation failed.: {1}".format(
                    module.params["name"], err
                )
            )

    module.exit_json(changed=changed)


def delete_nig(module, fusion):
    """Delete Network Interface Group"""
    changed = True
    nig_api_instance = purefusion.NetworkInterfaceGroupsApi(fusion)
    if not module.check_mode:
        try:
            nig_api_instance.delete_network_interface_group(
                availability_zone_name=module.params["availability_zone"],
                region_name=module.params["region"],
                network_interface_group_name=module.params["name"],
            )
        except purefusion.rest.ApiException:
            module.fail_json(
                msg="Delete Network Interface Group {0} failed.".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def update_nig(module, fusion, nig):
    """Update Network Interface Group"""
    changed = False
    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            display_name=dict(type="str"),
            availability_zone=dict(type="str", required=True, aliases=["az"]),
            region=dict(type="str", required=True),
            prefix=dict(type="str"),
            gateway=dict(type="str"),
            mtu=dict(type="int", default=1500),
            group_type=dict(type="str", default="eth", choices=["eth"]),
            state=dict(type="str", default="present", choices=["absent", "present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_NETADDR:
        module.fail_json(msg="netaddr module is required")

    state = module.params["state"]
    fusion = get_fusion(module)
    if module.params["prefix"]:
        if "/" not in module.params["prefix"]:
            module.fail_json(msg="Prefix must be in a CIDR format")
        if 8 > int(module.params["prefix"].split("/")[1]) > 32:
            module.fail_json(
                msg="An invalid CIDR notation has been provided: {0}".format(
                    module.params["prefix"]
                )
            )

    if not get_az(module, fusion):
        module.fail_json(msg="Availability Zone {0} does not exist")

    nig = get_nig(module, fusion)

    if state == "present" and not nig:
        if not module.params["prefix"]:
            module.fail_json(
                msg="When creating a new network interface group "
                "`prefix` must be provided"
            )
        create_nig(module, fusion)
    elif state == "present" and nig:
        # TODO: re-add this when SDK bug fixed
        module.exit_json(changed=False)
        # update_ps(module, fusion, subnet)
    elif state == "absent" and nig:
        delete_nig(module, fusion)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
