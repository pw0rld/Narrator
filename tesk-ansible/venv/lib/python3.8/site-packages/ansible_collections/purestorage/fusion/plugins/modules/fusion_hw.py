#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_hw
version_added: '1.0.0'
short_description:  Create hardware types in Pure Storage Fusion
description:
- Create a hardware type in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the hardware type.
    type: str
    required: true
  state:
    description:
    - Define whether the hardware type should exist or not.
    - Currently there is no mechanism to delete a hardware type
    default: present
    choices: [ present ]
    type: str
  display_name:
    description:
    - The human name of the hardware type.
    - If not provided, defaults to C(name)
    type: str
  media_type:
    description:
    - Volume size limit in M, G, T or P units.
    type: str
    required: true
  array_type:
    description:
    - The array type for the hardware type
    choices: [ FA//X, FA//C ]
    type: str
    required: true
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new hardware type foo
  purestorage.fusion.fusion_hw:
    name: foo
    array_type: "FA//X"
    media_type: NVME
    display_name: "NVME arrays"
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


def get_hw(module, fusion):
    """Get Hardware Type or None"""
    hw_api_instance = purefusion.HardwareTypesApi(fusion)
    try:
        return hw_api_instance.get_hardware_type(
            hardware_type_name=module.params["name"]
        )
    except purefusion.rest.ApiException:
        return None


def create_hw(module, fusion):
    """Create Hardware Type"""

    hw_api_instance = purefusion.HardwareTypesApi(fusion)

    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        try:
            hw_type = purefusion.HardwareTypePost(
                name=module.params["name"],
                array_type=module.params["array_type"],
                media_type=module.params["media_type"],
                display_name=display_name,
            )
            hw_api_instance.create_hardware_type(hw_type)
        except purefusion.rest.ApiException as err:
            module.fail_json(
                msg="Hardware Type {0} creation failed.: {1}".format(
                    module.params["name"], err
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
            array_type=dict(type="str", choices=["FA//X", "FA//C"], required=True),
            media_type=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    fusion = get_fusion(module)
    state = module.params["state"]
    h_type = get_hw(module, fusion)

    if not h_type and state == "present":
        create_hw(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
