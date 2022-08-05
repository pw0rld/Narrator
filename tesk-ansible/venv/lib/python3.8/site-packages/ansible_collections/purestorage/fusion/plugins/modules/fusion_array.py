#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_array
version_added: '1.0.0'
short_description:  Manage arrays in Pure Storage Fusion
description:
- Create or delete an array in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the array.
    type: str
    required: true
  state:
    description:
    - Define whether the array should exist or not.
    default: present
    choices: [ present, absent ]
    type: str
  display_name:
    description:
    - The human name of the array.
    - If not provided, defaults to C(name)
    type: str
  region:
    description:
    - The region the AZ is in
    type: str
    required: true
  availability_zone:
    aliases: [ az ]
    description:
    - The availability zone the array is located in.
    type: str
    required: true
  hardware_type:
    description:
    - Hardware type to which the storage class applies.
    choices: [ flash-array-x, flash-array-c, flash-array-x-optane, flash-array-xl ]
    required: true
    type: str
  host_name:
    description:
    - Management IP address of the array, or FQDN
    required: true
    type: str
  appliance_id:
    description:
    - Appliance ID of the array
    required: true
    type: str
  maintenance_mode:
    description:
    - Is the array in maintenance mode
    type: bool
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new array foo
  purestorage.fusion.fusion_array:
    name: foo
    az: zone_1
    hardware_type: bigfast
    display_name: "foo array"
    appliance_id: 1227571-198887878-35016350232000707
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

import math
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    get_fusion,
    fusion_argument_spec,
)


def wait_operation_finish(module, op_id, fusion):
    """
    wait_operation_finish wait until operation status is Succeeded or Failed. Then returns you that operation.
    if the operation takes longer than expected, it will raise an Exception
    """
    op_cli = purefusion.OperationsApi(fusion)
    while True:
        op = op_cli.get_operation(op_id)
        if op.status == "Succeeded" or op.status == "Failed":
            return op
        time.sleep(int(math.ceil(op.retry_in / 1000)))


def wait_operation_succeeded(module, op_id, fusion):
    """
    wait_operation_succeeded calls wait_operation_finish and expect the result is succeeded.
    if the operation is in other status, it will raise an expection
    """
    op = wait_operation_finish(module, op_id, fusion)
    if op.status == "Succeeded":
        return op
    else:
        # this is how we handle asynchronous error
        # if operation failed, the error field should be set. We can check it by op.error
        # op.error uses fusion.models.error.Error
        module.fail_json("Operation failed: {0}".format(op.error.message))


def get_array(module, fusion):
    """Return Array or None"""
    array_api_instance = purefusion.ArraysApi(fusion)
    try:
        return array_api_instance.get_array(
            array_name=module.params["name"],
            availability_zone_name=module.params["availability_zone"],
            region_name=module.params["region"],
        )
    except purefusion.rest.ApiException:
        return None


def create_array(module, fusion):
    """Create Array"""

    array_api_instance = purefusion.ArraysApi(fusion)

    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        try:
            array = purefusion.ArrayPost(
                hardware_type=module.params["hardware_type"],
                display_name=display_name,
                host_name=module.params["host_name"],
                name=module.params["name"],
                appliance_id=module.params["appliance_id"],
            )
            res = array_api_instance.create_array(
                array,
                availability_zone_name=module.params["availability_zone"],
                region_name=module.params["region"],
            )
            wait_operation_succeeded(module, res.id, fusion)
        except purefusion.rest.ApiException as err:
            module.fail_json(
                msg="Array {0} creation failed.: {1}".format(module.params["name"], err)
            )
        if module.params["maintenance_mode"] is not None:
            array = purefusion.ArrayPatch(
                maintenance_mode=purefusion.NullableBoolean(
                    module.params["maintenance_mode"]
                ),
            )
            res = array_api_instance.update_array(
                array,
                availability_zone_name=module.params["availability_zone"],
                region_name=module.params["region"],
                array_name=module.params["name"],
            )
            wait_operation_succeeded(module, res.id, fusion)
    module.exit_json(changed=changed)


def update_array(module, fusion, array):
    """Update Array"""
    array_api_instance = purefusion.ArraysApi(fusion)
    changed = False
    if (
        module.params["display_name"]
        and module.params["display_name"] != array.display_name
    ):
        display_name = module.params["display_name"]
        changed = True
        if not module.check_mode:
            array = purefusion.ArrayPatch(
                display_name=purefusion.NullableString(display_name),
            )
            res = array_api_instance.update_array(
                array,
                availability_zone_name=module.params["availability_zone"],
                region_name=module.params["region"],
                array_name=module.params["name"],
            )
            wait_operation_succeeded(module, res.id, fusion)
    if module.params["maintenance_mode"] is not None:
        if module.params["maintenance_mode"] != array.maintenance_mode:
            maint_mode = module.params["maintenance_mode"]
            changed = True
            if not module.check_mode:
                array = purefusion.ArrayPatch(
                    maintenance_mode=purefusion.NullableBoolean(maint_mode),
                )
                res = array_api_instance.update_array(
                    array,
                    availability_zone_name=module.params["availability_zone"],
                    region_name=module.params["region"],
                    array_name=module.params["name"],
                )
                wait_operation_succeeded(module, res.id, fusion)
    module.exit_json(changed=changed)


def delete_array(module, fusion):
    """Delete Array - not currently available"""
    array_api_instance = purefusion.ArraysApi(fusion)
    changed = True
    if not module.check_mode:
        try:
            res = array_api_instance.delete_array(
                region_name=module.params["region"],
                availability_zone_name=module.params["availability_zone"],
                array_name=module.params["name"],
            )
            wait_operation_succeeded(module, res.id, fusion)
        except purefusion.rest.ApiException as err:
            module.fail_json(
                msg="Array {0} creation failed.: {1}".format(module.params["name"], err)
            )
    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            availability_zone=dict(type="str", required=True, aliases=["az"]),
            display_name=dict(type="str"),
            region=dict(type="str", required=True),
            appliance_id=dict(type="str", required=True),
            host_name=dict(type="str", required=True),
            hardware_type=dict(
                type="str",
                required=True,
                choices=[
                    "flash-array-x",
                    "flash-array-c",
                    "flash-array-x-optane",
                    "flash-array-xl",
                ],
            ),
            maintenance_mode=dict(type="bool"),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    fusion = get_fusion(module)
    state = module.params["state"]
    array = get_array(module, fusion)

    if not array and state == "present":
        create_array(module, fusion)
    elif array and state == "present":
        update_array(module, fusion, array)
    elif array and state == "absent":
        delete_array(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
