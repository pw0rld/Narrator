#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_tenant
version_added: '1.0.0'
short_description:  Manage tenants in Pure Storage Fusion
description:
- Create,delete or update a tenant in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the tenant.
    type: str
    required: true
  state:
    description:
    - Define whether the tenant should exist or not.
    default: present
    choices: [ present, absent ]
    type: str
  display_name:
    description:
    - The human name of the tenant
    - If not provided, defaults to C(name)
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new tenat foo
  purestorage.fusion.fusion_tenant:
    name: foo
    display_name: "tenant foo"
    app_id: key_name
    key_file: "az-admin-private-key.pem"

- name: Delete tenat foo
  purestorage.fusion.fusion_tenant:
    name: foo
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


def get_tenant(module, fusion):
    """Return Tenant or None"""
    api_instance = purefusion.TenantsApi(fusion)
    try:
        return api_instance.get_tenant(tenant_name=module.params["name"])
    except purefusion.rest.ApiException:
        return None


def create_tenant(module, fusion):
    """Create Tenant"""

    api_instance = purefusion.TenantsApi(fusion)
    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        try:
            tenant = purefusion.TenantPost(
                name=module.params["name"],
                display_name=display_name,
            )
            api_instance.create_tenant(tenant)
        except purefusion.rest.ApiException as err:
            module.fail_json(
                msg="Tenant {0} creation failed.: {1}".format(
                    module.params["name"], err
                )
            )

    module.exit_json(changed=changed)


def update_tenant(module, fusion):
    """Update Tenant settings"""
    changed = False
    api_instance = purefusion.TenantsApi(fusion)

    tenant = api_instance.get_tenant(
        tenant_name=module.params["name"],
    )
    if (
        module.params["display_name"]
        and module.params["display_name"] != tenant.display_name
    ):
        changed = True
        if not module.check_mode:
            new_tenant = purefusion.TenantPatch(
                display_name=purefusion.NullableString(module.params["display_name"]),
            )
            try:
                api_instance.update_tenant(
                    new_tenant,
                    tenant_name=module.params["name"],
                )
            except purefusion.rest.ApiException as err:
                module.fail_json(
                    msg="Changing tenant display_name failed: {0}".format(err)
                )

    module.exit_json(changed=changed)


def delete_tenant(module, fusion):
    """Delete Tenant"""
    changed = True
    api_instance = purefusion.TenantsApi(fusion)
    if not module.check_mode:
        try:
            api_instance.delete_tenant(tenant_name=module.params["name"])
        except purefusion.rest.ApiException as err:
            module.fail_json(
                msg="Deleting Tenant {0} failed: {1}".format(module.params["name"], err)
            )

    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            display_name=dict(type="str"),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    fusion = get_fusion(module)
    state = module.params["state"]
    tenant = get_tenant(module, fusion)

    if not tenant and state == "present":
        create_tenant(module, fusion)
    elif tenant and state == "present":
        update_tenant(module, fusion)
    elif tenant and state == "absent":
        delete_tenant(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
