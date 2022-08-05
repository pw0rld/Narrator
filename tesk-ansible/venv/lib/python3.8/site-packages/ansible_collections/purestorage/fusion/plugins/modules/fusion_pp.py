#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_pp
version_added: '1.0.0'
short_description:  Manage protection policies in Pure Storage Fusion
description:
- Create protection policies in Pure Storage Fusion.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the protection policy.
    type: str
    required: true
  state:
    description:
    - Define whether the protection policy should exist or not.
    - Currently there is no mechanism to delete or update a protection policy
    default: present
    choices: [ present ]
    type: str
  display_name:
    description:
    - The human name of the protection policy.
    - If not provided, defaults to C(name)
    type: str
  local_rpo:
    description:
    - Recovery Point Objective for snapshots
    - Value should be specified in minutes
    - Minimum value is 10 minutes
    type: int
    required: true
  local_retention:
    description:
    - Retention Duration for periodic snapshots
    - Minimum value is 1 minute
    - Value can be provided as m(inutes), h(ours),
      d(ays), w(eeks), or y(ears)
    - if no unit is provided, minutes are assumed
    - Must be between 1MB/s and 512GB/s
    type: str
    required: true
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new protection policy foo
  purestorage.fusion.fusion_pp:
    name: foo
    local_rpo: 10
    local_retention: 4d
    display_name: "foo pp"
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


def human_to_minutes(period):
    """Given a human-readable period (e.g. 2d, 3w),
    return the number of minutes.  Will return 0 if the argument has
    unexpected form.
    """
    minutes = period[:-1]
    unit = period[-1].lower()
    if minutes.isdigit():
        minutes = int(minutes)
        if unit == "y":
            minutes *= 524160
        elif unit == "w":
            minutes *= 10080
        elif unit == "d":
            minutes *= 1440
        elif unit == "h":
            minutes *= 60
        else:
            minutes = 0
    else:
        minutes = 0
    return minutes


def get_pp(module, fusion):
    """Return Protection Policy or None"""
    pp_api_instance = purefusion.ProtectionPoliciesApi(fusion)
    try:
        return pp_api_instance.get_protection_policy(
            protection_policy_name=module.params["name"]
        )
    except purefusion.rest.ApiException:
        return None


def create_pp(module, fusion):
    """Create Protection Policy"""

    pp_api_instance = purefusion.ProtectionPoliciesApi(fusion)
    local_retention = human_to_minutes(module.params["local_retention"])
    if local_retention < 1:
        module.fail_json(msg="Local Retention must be a minimum of 1 minutes")
    if module.params["local_rpo"] < 10:
        module.fail_json(msg="Local RPO must be a minimum of 10 minutes")
    changed = True
    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        try:
            pp_api_instance.create_protection_policy(
                purefusion.ProtectionPolicyPost(
                    name=module.params["name"],
                    display_name=display_name,
                    objectives=[
                        {
                            "type": "RPO",
                            "rpo": "PT" + str(module.params["local_rpo"]) + "M",
                        },
                        {
                            "type": "Retention",
                            "after": "PT" + str(local_retention) + "M",
                        },
                    ],
                )
            )
        except purefusion.rest.ApiException as err:
            module.fail_json(
                msg="Protection Policy {0} creation failed.: {1}".format(
                    module.params["name"], err
                )
            )

    module.exit_json(changed=changed)


def delete_pp(module, fusion):
    """Delete Protection Policy - not available unitl 1.1"""
    changed = False
    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            display_name=dict(type="str"),
            local_rpo=dict(type="int", required=True),
            local_retention=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["present"]),
        )
    )
    module = AnsibleModule(argument_spec, supports_check_mode=True)

    fusion = get_fusion(module)
    state = module.params["state"]
    policy = get_pp(module, fusion)

    if not policy and state == "present":
        create_pp(module, fusion)
    elif policy and state == "absent":
        delete_pp(module, fusion)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
