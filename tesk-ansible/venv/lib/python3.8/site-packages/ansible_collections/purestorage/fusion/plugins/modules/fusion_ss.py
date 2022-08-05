#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_ss
version_added: '1.0.0'
short_description:  Manage storage services in Pure Storage Fusion
description:
- Create or update a storage services in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the storage service.
    type: str
    required: true
  state:
    description:
    - Define whether the storage service should exist or not.
    - Currently there is no mechanism to delete a storage service
    default: present
    choices: [ present ]
    type: str
  display_name:
    description:
    - The human name of the storage service.
    - If not provided, defaults to C(name)
    type: str
  hardware_types:
    description:
    - Hardware types to which the storage service applies.
    required: true
    type: list
    elements: str
    choices: [ flash-array-x, flash-array-c, flash-array-x-optane, flash-array-xl ]
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new storage service foo
  purestorage.fusion.fusion_ss:
    name: foo
    hardware_type:
    - flash-array-x
    - flash-array-x-optane
    display_name: "test class"
    app_id: key_name
    key_file: "az-admin-private-key.pem"

- name: Update storage service
  purestorage.fusion.fusion_ss:
    name: foo
    display_name: "main class"
    hardware_types:
    - flash-array-c
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


def get_ss(module, fusion):
    """Return Storage Service or None"""
    ss_api_instance = purefusion.StorageServicesApi(fusion)
    try:
        return ss_api_instance.get_storage_service(
            storage_service_name=module.params["name"]
        )
    except purefusion.rest.ApiException:
        return None


def create_ss(module, fusion):
    """Create Storage Service"""

    ss_api_instance = purefusion.StorageServicesApi(fusion)

    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        try:
            s_service = purefusion.StorageServicePost(
                name=module.params["name"],
                display_name=display_name,
                hardware_types=module.params["hardware_types"],
            )
            res = ss_api_instance.create_storage_service(s_service)
        except purefusion.rest.ApiException:
            module.fail_json(
                msg="Storage Service {0} creation failed.: {1}".format(
                    module.params["name"], res.error
                )
            )

    module.exit_json(changed=changed)


def update_ss(module, fusion):
    """Update Storage Service"""
    changed = False
    ss_api_instance = purefusion.StorageServicesApi(fusion)

    s_service = ss_api_instance.get_storage_service(
        storage_service_name=module.params["name"],
    )
    hw_types = []
    for hw_type in range(0, len(s_service.hardware_types)):
        hw_types.append(s_service.hardware_types[hw_type].name)
    if (
        module.params["display_name"]
        and module.params["display_name"] != s_service.display_name
    ):
        changed = True
        display_name = module.params["display_name"]
    else:
        display_name = s_service.display_name
    if changed and not module.check_mode:
        sservice = purefusion.StorageServicePatch(
            display_name=purefusion.NullableString(display_name),
        )
        try:
            res = ss_api_instance.update_storage_service(
                sservice,
                storage_service_name=module.params["name"],
            )
        except purefusion.rest.ApiException:
            module.fail_json(
                msg="Changing storage service {0} failed. Error: {1}".format(
                    module.params["name"], res.error
                )
            )
    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            display_name=dict(type="str"),
            hardware_types=dict(
                type="list",
                required=True,
                elements="str",
                choices=[
                    "flash-array-x",
                    "flash-array-c",
                    "flash-array-x-optane",
                    "flash-array-xl",
                ],
            ),
            state=dict(type="str", default="present", choices=["present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    fusion = get_fusion(module)
    state = module.params["state"]
    s_service = get_ss(module, fusion)

    if not s_service and state == "present":
        create_ss(module, fusion)
    elif s_service and state == "present":
        update_ss(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
