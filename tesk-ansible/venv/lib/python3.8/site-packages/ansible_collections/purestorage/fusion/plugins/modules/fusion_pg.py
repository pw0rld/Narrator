#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_pg
version_added: '1.0.0'
short_description:  Manage placement groups in Pure Storage Fusion
description:
- Create, update or delete a placement groups in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the placement group.
    type: str
    required: true
  display_name:
    description:
    - The human name of the placement group.
    - If not provided, defaults to C(name)
    type: str
  state:
    description:
    - Define whether the placement group should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  tenant:
    description:
    - The name of the tenant.
    type: str
    required: true
  tenant_space:
    description:
    - The name of the tenant space.
    type: str
    required: true
  availability_zone:
    aliases: [ az ]
    description:
    - The name of the availability zone to create the placement group in.
    type: str
  placement_engine:
    description:
    - For workload placement recommendations from Pure1 Meta, use I(pure1meta).
    - Please note that this might increase volume creation time..
    type: str
    choices: [ heuristics, pure1meta ]
    default: heuristics
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new placement group named foo
  purestorage.fusion.fusion_pg:
    name: foo
    tenant: test
    tenant_space: space_1
    availability_zone: az1
    placement_engine: pure1meta
    state: present
    app_id: key_name
    key_file: "az-admin-private-key.pem"

- name: Delete placement group foo
  purestorage.fusion.fusion_pg:
    name: foo
    tenant: test
    tenant_space: space_1
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    get_fusion,
    fusion_argument_spec,
)


def get_ts(module, fusion):
    """Tenant Space or None"""
    ts_api_instance = purefusion.TenantSpacesApi(fusion)
    try:
        return ts_api_instance.get_tenant_space(
            tenant_name=module.params["tenant"],
            tenant_space_name=module.params["tenant_space"],
        )
    except purefusion.rest.ApiException:
        return None


def get_az(module, fusion):
    """Availability Zone or None"""
    api_instance = purefusion.AvailabilityZonesApi(fusion)
    try:
        return api_instance.get_availability_zone(
            availability_zone_name=module.params["availability_zone"]
        )
    except purefusion.rest.ApiException:
        return None


def get_tenant(module, fusion):
    """Return Tenant or None"""
    api_instance = purefusion.TenantsApi(fusion)
    try:
        return api_instance.get_tenant(tenant_name=module.params["tenant"])
    except purefusion.rest.ApiException:
        return None


def get_pg(module, fusion):
    """Return Placement Group or None"""
    pg_api_instance = purefusion.PlacementGroupsApi(fusion)
    try:
        return pg_api_instance.get_placement_group(
            tenant_name=module.params["tenant"],
            tenant_space_name=module.params["tenant_space"],
            placement_group_name=module.params["name"],
        )
    except purefusion.rest.ApiException:
        return None


def create_pg(module, fusion):
    """Create Placement Group"""

    pg_api_instance = purefusion.PlacementGroupsApi(fusion)

    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        try:
            group = purefusion.PlacementGroupPost(
                placement_engine=module.params["placement_engine"].lower(),
                availability_zone=module.params["availability_zone"],
                name=module.params["name"],
                display_name=display_name,
            )
            pg_api_instance.create_placement_group(
                group,
                tenant_name=module.params["tenant"],
                tenant_space_name=module.params["tenant_space"],
            )
        except purefusion.rest.ApiException as err:
            module.fail_json(
                msg="Placement Group {0} creation failed.: {1}".format(
                    module.params["name"], err
                )
            )

    module.exit_json(changed=changed)


def delete_pg(module, fusion):
    """Delete Placement Group"""
    changed = True
    pg_api_instance = purefusion.PlacementGroupsApi(fusion)
    if not module.check_mode:
        try:
            pg_api_instance.delete_placement_group(
                placement_group_name=module.params["name"],
                tenant_name=module.params["tenant"],
                tenant_space_name=module.params["tenant_space"],
            )
        except purefusion.rest.ApiException:
            module.fail_json(
                msg="Delete Placement Group {0} failed.".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            display_name=dict(type="str"),
            tenant=dict(type="str", required=True),
            tenant_space=dict(type="str", required=True),
            availability_zone=dict(type="str", aliases=["az"]),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            placement_engine=dict(
                type="str", default="heuristics", choices=["heuristics", "pure1meta"]
            ),
        )
    )

    required_if = [["state", "present", ["availability_zone", "placement_engine"]]]
    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    state = module.params["state"]
    fusion = get_fusion(module)
    pgroup = get_pg(module, fusion)
    if not (
        get_az(module, fusion) and get_tenant(module, fusion) and get_ts(module, fusion)
    ):
        module.fail_json(
            msg="Please check the values for `availability_zone`, `tenant` "
            "and `tenant_space` to ensure they all exsit and have appropriate relationships."
        )
    if state == "present" and not pgroup:
        create_pg(module, fusion)
    elif state == "absent" and pgroup:
        delete_pg(module, fusion)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
