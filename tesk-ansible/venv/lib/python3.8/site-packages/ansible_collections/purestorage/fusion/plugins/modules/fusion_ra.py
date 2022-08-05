#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_ra
version_added: '1.0.0'
short_description:  Manage role assignments in Pure Storage Fusion
description:
- Create or delete a storage class in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the role to be assigned/unassigned.
    type: str
    required: true
  state:
    description:
    - Define whether the role assingment should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  user:
    description:
    - The username to assign the role to.
    - Currently this only supports the Pure1 App ID
    - This should be provide in the same format as the `app_id` parameter
    required: true
    type: str
  scope:
    description:
    - The level to which the role is assigned
    choices: [ organization, tenant, tenant_space ]
    default: organization
    type: str
  tenant:
    description:
    - The name of the tenant the user has the role applied to
    - Must be provided if `scope` is set to either `tenant` or `tenant_space`
    type: str
  tenant_space:
    description:
    - The name of the tenant_space the user has the role applied to
    - Must be provided if `scope` is set to `tenant_space`
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Assign role foo to user in tenant bar
  purestorage.fusion.fusion_ra:
    name: foo
    user: key_name
    tenant: bar
    app_id: key_name
    key_file: "az-admin-private-key.pem"

- name: Delete role foo from user in tenant bar
  purestorage.fusion.fusion_ra:
    name: foo
    user: key_name
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


def human_to_principal(fusion, user_id):
    """Given a human readable Fusion user, such as a Pure 1 App ID
    return the associated principal
    """
    principal = None
    id_api_instance = purefusion.IdentityManagerApi(fusion)
    users = id_api_instance.list_users()
    for user in range(0, len(users)):
        if users[user].name == user_id:
            principal = users[user].id
    return principal


def human_to_scope(params):
    """Given a scope type and associated tenant
    and tenant_space, return the scope_link
    """
    scope_link = None
    if params["scope"] == "organization":
        scope_link = "/"
    elif params["scope"] == "tenant":
        scope_link = "/tenants/" + params["tenant"]
    elif params["scope"] == "tenant_space":
        scope_link = (
            "/tenants/" + params["tenant"] + "/tenant-spaces/" + params["tenant_space"]
        )
    return scope_link


def get_role(module, fusion):
    """Return Role or None"""
    role_api_instance = purefusion.RolesApi(fusion)
    try:
        return role_api_instance.get_role(role_name=module.params["name"])
    except purefusion.rest.ApiException:
        return None


def get_ra(module, fusion):
    """Return Role Assignment or None"""
    ra_api_instance = purefusion.RoleAssignmentsApi(fusion)
    try:
        assignments = ra_api_instance.list_role_assignments(
            role_name=module.params["name"]
        )
        for assign in range(0, len(assignments)):
            principal = human_to_principal(fusion, module.params["user"])
            scope = human_to_scope(module.params)
            if (
                assignments[assign].principal == principal
                and assignments[assign].scope.self_link == scope
            ):
                return assignments[assign]
        return None
    except purefusion.rest.ApiException:
        return None


def get_tenant(module, fusion):
    """Return tenant or None"""
    t_api_instance = purefusion.TenantsApi(fusion)
    try:
        return t_api_instance.get_tenant(tenant_name=module.params["tenant"])
    except purefusion.rest.ApiException:
        return None


def get_ts(module, fusion):
    """Return tenant space or None"""
    ts_api_instance = purefusion.TenantSpacesApi(fusion)
    try:
        return ts_api_instance.get_tenant_space(
            tenant_space_name=module.params["tenant_space"],
            tenant_name=module.params["tenant"],
        )
    except purefusion.rest.ApiException:
        return None


def create_ra(module, fusion):
    """Create Role Assignment"""

    ra_api_instance = purefusion.RoleAssignmentsApi(fusion)

    changed = True
    if not module.check_mode:
        scope = human_to_scope(module.params)
        principal = human_to_principal(fusion, module.params["user"])
        assignment = purefusion.RoleAssignmentPost(scope=scope, principal=principal)
        try:
            ra_api_instance.create_role_assignment(
                assignment, role_name=module.params["name"]
            )
        except purefusion.rest.ApiException:
            module.fail_json(
                msg="{0} level Role Assignment creation for user {1} failed".format(
                    module.params["scope"], module.params["user"]
                )
            )
    module.exit_json(changed=changed)


def delete_ra(module, fusion):
    """Delete Role Assignment"""
    changed = True
    ra_api_instance = purefusion.RoleAssignmentsApi(fusion)
    if not module.check_mode:
        ra_name = get_ra(module, fusion).name
        try:
            ra_api_instance.delete_role_assignment(
                role_name=module.params["name"], role_assignment_name=ra_name
            )
        except purefusion.rest.ApiException:
            module.fail_json(
                msg="{0} level Role Assignment delete for user {1} failed".format(
                    module.params["scope"], module.params["user"]
                )
            )

    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            tenant=dict(type="str"),
            tenant_space=dict(type="str"),
            user=dict(type="str", required=True),
            scope=dict(
                type="str",
                default="organization",
                choices=["organization", "tenant", "tenant_space"],
            ),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    required_if = [
        ["scope", "tenant", ["tenant"]],
        ["scope", "tenant_space", ["tenant", "tenant_space"]],
    ]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    fusion = get_fusion(module)
    state = module.params["state"]
    if not human_to_principal(fusion, module.params["user"]):
        module.fail_json(msg="User {0} does not exist".format(module.params["user"]))
    if module.params["tenant"] and not get_tenant(module, fusion):
        module.fail_json(
            msg="Tenant {0} does not exist".format(module.params["tenant"])
        )
    if module.params["tenant_space"] and not get_ts(module, fusion):
        module.fail_json(
            msg="Tenant Space {0} does not exist".format(module.params["tenant_space"])
        )
    role_assignment = get_ra(module, fusion)

    if not role_assignment and state == "present":
        create_ra(module, fusion)
    elif role_assignment and state == "absent":
        delete_ra(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
