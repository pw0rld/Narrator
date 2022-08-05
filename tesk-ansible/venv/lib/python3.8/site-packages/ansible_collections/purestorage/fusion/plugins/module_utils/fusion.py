# -*- coding: utf-8 -*-

# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c), Simon Dodsley <simon@purestorage.com>,2021
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

HAS_FUSION = True
try:
    import fusion
except ImportError:
    HAS_FUSION = False

from os import environ
import platform

TOKEN_EXCHANGE_URL = "https://api.pure1.purestorage.com/oauth2/1.0/token"
VERSION = 1.0
USER_AGENT_BASE = "Ansible"


def get_fusion(module):
    """Return System Object or Fail"""
    user_agent = "%(base)s %(class)s/%(version)s (%(platform)s)" % {
        "base": USER_AGENT_BASE,
        "class": __name__,
        "version": VERSION,
        "platform": platform.platform(),
    }
    app_id = module.params["app_id"]
    key_file = module.params["key_file"]
    if HAS_FUSION:
        config = fusion.Configuration()
        if app_id and key_file:
            try:
                config.issuer_id = app_id
                config.private_key_file = key_file
                client = fusion.ApiClient(config)
                client.set_default_header("User-Agent", user_agent)
            except Exception:
                module.fail_json(msg="Unknown failure. Please contact Pure Support")
        elif environ.get("FUSION_APP_ID") and environ.get("FUSION_PRIVATE_KEY_FILE"):
            try:
                config.issuer_id = environ.get("FUSION_APP_ID")
                config.private_key_file = environ.get("FUSION_PRIVATE_KEY_FILE")
                client = fusion.ApiClient(config)
                client.set_default_header("User-Agent", user_agent)
            except Exception:
                module.fail_json(msg="Unknown failure. Please contact Pure Support")
        else:
            module.fail_json(
                msg="You must set FUSION_APP_ID and FUSION_PRIVATE_KEY_FILE environment variables "
                "or the app_id and key_file module arguments"
            )
        try:
            api_instance = fusion.DefaultApi(client)
            api_instance.get_version()
        except Exception as err:
            module.fail_json(msg="Fusion authentication failed: {0}".format(err))
    else:
        module.fail_json(msg="fusion SDK is not installed.")
    return client


def fusion_argument_spec():
    """Return standard base dictionary used for the argument_spec argument in AnsibleModule"""

    return dict(
        app_id=dict(no_log=True, required=True),
        key_file=dict(no_log=False, required=True),
    )
