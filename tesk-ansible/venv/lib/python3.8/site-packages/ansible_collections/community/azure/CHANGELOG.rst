=============================
Community Azure Release Notes
=============================

.. contents:: Topics


v1.1.0
======

Release Summary
---------------

The community.azure Ansible collection is being deprecated in favor of azure.azcollection which provide the same modules in addition to maintenance and updates (https://github.com/ansible-collections/community.azure/pull/24).

Deprecated Features
-------------------

- All community.azure.azure_rm_<resource>_facts modules are deprecated. Use azure.azcollection.azure_rm_<resource>_info modules instead (https://github.com/ansible-collections/community.azure/pull/24).
- All community.azure.azure_rm_<resource>_info modules are deprecated. Use azure.azcollection.azure_rm_<resource>_info modules instead (https://github.com/ansible-collections/community.azure/pull/24).
- community.azure.azure_rm_managed_disk and community.azure.azure_rm_manageddisk are deprecated. Use azure.azcollection.azure_rm_manageddisk instead (https://github.com/ansible-collections/community.azure/pull/24).
- community.azure.azure_rm_virtualmachine_extension and community.azure.azure_rm_virtualmachineextension are deprecated. Use azure.azcollection.azure_rm_virtualmachineextension instead (https://github.com/ansible-collections/community.azure/pull/24).
- community.azure.azure_rm_virtualmachine_scaleset and community.azure.azure_rm_virtualmachinescaleset are deprecated. Use azure.azcollection.azure_rm_virtualmachinescaleset instead (https://github.com/ansible-collections/community.azure/pull/24).
