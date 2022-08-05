#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_ts
version_added: '1.0.0'
short_description:  Manage tenant spaces in Pure Storage Fusion
description:
- Create, update or delete a tenant spaces in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the tenant `space.
    type: str
    required: true
  display_name:
    description:
    - The human name of the tenant space.
    - If not provided, defaults to C(name)
    type: str
  state:
    description:
    - Define whether the tenant space should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  tenant:
    description:
    - The name of the tenant.
    type: str
    required: true
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new teanat space foo for tenany bar
  purestorage.fusion.fusion_ts:
    name: foo
    tenant: bar
    state: present
    app_id: key_name
    key_file: "az-admin-private-key.pem"

- name: Delete tenant space foo in tenant bar
  purestorage.fusion.fusion_ts:
    name: foo
    tenant: bar
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
            tenant_space_name=module.params["name"],
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


def create_ts(module, fusion):
    """Create Tenant Space"""

    ts_api_instance = purefusion.TenantSpacesApi(fusion)

    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        try:
            tspace = purefusion.TenantSpacePost(
                name=module.params["name"],
                display_name=display_name,
            )
            ts_api_instance.create_tenant_space(
                tspace,
                tenant_name=module.params["tenant"],
            )
        except purefusion.rest.ApiException as err:
            module.fail_json(
                msg="Tenant Space {0} creation failed.: {1}".format(
                    module.params["name"], err
                )
            )

    module.exit_json(changed=changed)


def delete_ts(module, fusion):
    """Delete Tenant Space"""
    changed = True
    ts_api_instance = purefusion.TenantSpacesApi(fusion)
    if not module.check_mode:
        try:
            ts_api_instance.delete_tenant_space(
                tenant_name=module.params["tenant"],
                tenant_space_name=module.params["name"],
            )
        except purefusion.rest.ApiException:
            module.fail_json(
                msg="Delete Tenant Space {0} failed.".format(module.params["name"])
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
            state=dict(type="str", default="present", choices=["absent", "present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    fusion = get_fusion(module)
    if not get_tenant(module, fusion):
        module.fail_json(msg="Tenant {0} does not exist")
    tspace = get_ts(module, fusion)
    if state == "present" and not tspace:
        create_ts(module, fusion)
    elif state == "absent" and tspace:
        delete_ts(module, fusion)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
