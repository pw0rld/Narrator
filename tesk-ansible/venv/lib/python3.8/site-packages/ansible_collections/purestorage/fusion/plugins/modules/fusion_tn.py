#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_tn
version_added: '1.0.0'
short_description:  Manage tenant networks in Pure Storage Fusion
description:
- Create or delete tenant networks in Pure Storage Fusion.
- Currently this only supports a single tenant subnet per tenant network
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the tenant network.
    type: str
    required: true
  display_name:
    description:
    - The human name of the tenant network.
    - If not provided, defaults to C(name)
    type: str
  state:
    description:
    - Define whether the tenant network should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  availability_zone:
    aliases: [ az ]
    description:
    - The name of the availability zone for the tenant network.
    type: str
    required: true
  provider_subnets:
    description:
    - List of provider subnets to assign to the tenant networks subnet
    type: list
    elements: str
  addresses:
    description:
    - List of IP addresses to be used in the subnet of the tenant network
    - IP addresses must include a CIDR notation
    - IPv4 and IPv6 are fully supported
    type: list
    elements: str
  gateway:
    description:
    - Address of the subnet gateway
    - Currently this must be provided
    type: str
  mtu:
    description:
    - MTYU setting for the subnet
    default: 1500
    type: int
  prefix:
    description:
    - Network prefix in CIDR format
    - This will be deprecated soon
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new tenant network foo in AZ bar
  purestorage.fusion.fusion_tn:
    name: foo
    availability_zone: bar
    mtu: 9000
    gateway: 10.21.200.1
    addresses:
      - 10.21.200.124/24
      - 10.21.200.36/24
    provider_subnets:
      - subnet-0
    state: present
    app_id: key_name
    key_file: "az-admin-private-key.pem"

- name: Delete tenant network foo in AZ bar
  purestorage.fusion.fusion_tn:
    name: foo
    availability_zone: bar
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


def get_ps(module, fusion):
    """Check all Provider Subnets"""
    ps_api_instance = purefusion.ProviderSubnetsApi(fusion)
    for subnet in range(0, len(module.params["provider_subnets"])):
        try:
            ps_api_instance.get_provider_subnet(
                availability_zone_name=module.params["availability_zone"],
                provider_subnet=module.params["provider_subnets"][subnet],
            )
        except purefusion.rest.ApiException:
            return False
    return True


def get_az(module, fusion):
    """Availability Zone or None"""
    az_api_instance = purefusion.AvailabilityZonesApi(fusion)
    try:
        return az_api_instance.get_availability_zone(
            availability_zone_name=module.params["availability_zone"],
        )
    except purefusion.rest.ApiException:
        return None


def get_tn(module, fusion):
    """Tenant Network or None"""
    api_instance = purefusion.TenantNetworksApi(fusion)
    try:
        return api_instance.get_tenant_network(
            tenant_network=module.params["name"],
            availability_zone_name=module.params["availability_zone"],
        )
    except purefusion.rest.ApiException:
        return None


def create_tn(module, fusion):
    """Create Tenant Network"""

    tn_api_instance = purefusion.TenantNetworksApi(fusion)

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
            if module.params["gateway"]:
                tsubnet = purefusion.TenantSubnetPost(
                    prefix=module.params["prefix"],
                    addresses=module.params["addresses"],
                    gateway=module.params["gateway"],
                    mtu=module.params["mtu"],
                    provider_subnets=module.params["provider_subnets"],
                )
            else:
                tsubnet = purefusion.TenantSubnetPost(
                    prefix=module.params["prefix"],
                    addresses=module.params["addresses"],
                    mtu=module.params["mtu"],
                    provider_subnets=module.params["provider_subnets"],
                )
            tnet = purefusion.TenantNetworkPost(
                tenant_subnets=[tsubnet],
                name=module.params["name"],
                display_name=display_name,
            )
            tn_api_instance.create_tenant_network(
                tnet,
                availability_zone_name=module.params["availability_zone"],
            )
        except purefusion.rest.ApiException as err:
            module.fail_json(
                msg="Tenant Network {0} creation failed.: {1}".format(
                    module.params["name"], err
                )
            )

    module.exit_json(changed=changed)


def delete_tn(module, fusion):
    """Delete Tenant Network"""
    changed = True
    tn_api_instance = purefusion.TenantNetworksApi(fusion)
    if not module.check_mode:
        try:
            tn_api_instance.delete_tenant_network(
                availability_zone_name=module.params["availability_zone"],
                tenant_network=module.params["name"],
            )
        except purefusion.rest.ApiException:
            module.fail_json(
                msg="Delete Tenant Network {0} failed.".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def update_tn(module, fusion, tenant_network):
    """Update Tenant Network"""
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
            prefix=dict(type="str"),
            gateway=dict(type="str"),
            mtu=dict(type="int", default=1500),
            provider_subnets=dict(type="list", elements="str"),
            addresses=dict(type="list", elements="str"),
            state=dict(type="str", default="present", choices=["absent", "present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_NETADDR:
        module.fail_json(msg="netaddr module is required")

    state = module.params["state"]
    fusion = get_fusion(module)
    if not get_az(module, fusion):
        module.fail_json(msg="Availability Zone {0} does not exist")
    if module.params["provider_subnets"] and not get_ps(module, fusion):
        module.fail_json(
            msg="Not all of the provider subnets exist in the specified AZ"
        )
    for address in range(0, len(module.params["addresses"])):
        if "/" not in module.params["addresses"][address]:
            module.fail_json(msg="All addresses must include a CIDR notation")
        if 8 > int(module.params["addresses"][address].split("/")[1]) > 32:
            module.fail_json(
                msg="An invalid CIDR notation has been provided: {0}".format(
                    module.params["addresses"][address]
                )
            )

    tnet = get_tn(module, fusion)

    if state == "present" and not tnet:
        if not (
            module.params["addresses"]
            and module.params["gateway"]  # Soon to be optional
            and module.params["prefix"]  # To be removed soon
            and module.params["provider_subnets"]
        ):
            module.fail_json(
                msg="When creating a new tenant network, the following "
                "parameters must be supplied: `gateway`, `addresses`, `prefix` "
                "and `provider_subnets`"
            )
        create_tn(module, fusion)
    elif state == "present" and tnet:
        update_tn(module, fusion, tnet)
    elif state == "absent" and tnet:
        delete_tn(module, fusion)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
