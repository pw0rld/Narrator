# A Makefile for creating, running and testing Infindat's Ansible collection.

### Dependencies ###
# - jq: https://stedolan.github.io/jq/
# - spruce: https://github.com/geofffranks/spruce

### environment ###
# Include an env file with secrets.  This exposes the secrets
# as envvars only for the life of make.  It does not
# pollute the environment persistently.
# Format:
# API_KEY=someAnsibleGalaxyApiKey
# The key only needs to be valid to use target galaxy-colletion-publish.
_env = ~/.ssh/ansible-galaxy.sh
include $(_env)
export $(shell sed 's/=.*//' $(_env))

# Use color in Makefiles.
# _use_color = true

include Makefile-help

### Vars ###
_version            = $(shell spruce json galaxy.yml | jq '.version'   | sed 's?"??g')
_namespace          = $(shell spruce json galaxy.yml | jq '.namespace' | sed 's?"??g')
_name               = $(shell spruce json galaxy.yml | jq '.name'      | sed 's?"??g')
_install_path       = ~/.ansible/collections
_install_path_local = $$HOME/.ansible/collections
_venv               = venv
#_install_path_local = /opt/atest
_requirements_file  = requirements_2.10.txt
_user               = psus-gitlab-cicd
_ibox_url           = ibox1521
SHELL               = /bin/bash

##@ General
_check-vars:
ifeq ($(strip $(API_KEY)),)
	@echo "API_KEY variable is unset" && false
endif

env-show: _check-vars
	@echo "API_KEY=[ set but redacted ]"

version: _check-vars  ## Show versions.
	ansible --version
	@echo
	ansible-Galaxy collection list

_test-venv:
	@# Test that a venv is activated
ifndef VIRTUAL_ENV
	@echo "Error: Virtual environment not set"
	@echo -e "\nRun:\n  make pyvenv"
	@echo -e "  source $(_venv)/bin/activate\n"
	exit 1
endif
	@echo "Virtual environment set"

##@ Galaxy
galaxy-collection-build:  ## Build the collection.
	@eval $(_begin)
	rm -rf collections/
	ansible-galaxy collection build
	@eval $(_finish)

galaxy-collection-build-force: ## Force build the collection. Overwrite an existing collection file.
	@eval $(_begin)
	ansible-galaxy collection build --force
	@eval $(_finish)

galaxy-collection-publish: _check-vars  ## Publish the collection to https://galaxy.ansible.com/ using the API key provided.
	@eval $(_begin)
	ansible-galaxy collection publish --api-key $(API_KEY) ./$(_namespace)-$(_name)-$(_version).tar.gz -vvv
	@eval $(_finish)

galaxy-collection-install:  ## Download and install from galaxy.ansible.com. This will wipe $(_install_path).
	@eval $(_begin)
	ansible-galaxy collection install $(_namespace).$(_name) --collections-path $(_install_path) --force
	@eval $(_finish)

galaxy-collection-install-locally:  ## Download and install from local tar file.
	@eval $(_begin)
	ansible-galaxy collection install --force $(_namespace)-$(_name)-$(_version).tar.gz --collections-path $(_install_path_local)
	@eval $(_finish)

##@ Playbooks Testing
_test_playbook:
	@# Run a playbook specified by an envvar.
	@# See DEV_README.md
	cd playbooks && \
		ansible-playbook \
			--extra-vars "@../ibox_vars/iboxCICD.yaml" \
			--ask-vault-pass \
			"$$playbook_name"

test-create-resources:  ## Run full creation test suite as run by Gitlab CICD.
	@eval $(_begin)
	playbook_name=test_create_resources.yml $(_make) _test_playbook
	@eval $(_finish)

test-remove-resources:  ## Run full removal  test suite as run by Gitlab CICD.
	@eval $(_begin)
	playbook_name=test_remove_resources.yml $(_make) _test_playbook
	@eval $(_finish)

test-create-snapshots:  ## Test creating immutable snapshots.
	@eval $(_begin)
	playbook_name=test_create_snapshots.yml $(_make) _test_playbook
	@eval $(_finish)

test-remove-snapshots:  ## Test removing immutable snapshots (teardown).
	@eval $(_begin)
	playbook_name=test_remove_snapshots.yml $(_make) _test_playbook
	@eval $(_finish)

test-create-map-cluster:  ## Run full creation test suite as run by Gitlab CICD.
	@eval $(_begin)
	playbook_name=test_create_map_cluster.yml $(_make) _test_playbook
	@eval $(_finish)

test-remove-map-cluster:  ## Run full removal  test suite as run by Gitlab CICD.
	@eval $(_begin)
	playbook_name=test_remove_map_cluster.yml $(_make) _test_playbook
	@eval $(_finish)

### ansible-test ###
test-sanity:
	@# Run ansible sanity tests in accordance with
	@# https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#testing-collections
	@# This runs on an collection installed from galaxy. This makes it
	@# somewhat useless for dev and debugging. Use target test-sanity-locally.
	cd $(_install_path)/ansible_collections/infinidat/infinibox && \
		ansible-test sanity --docker default -v

_setup-sanity-locally:
	@# Setup a test env.
	cd $(_install_path_local)/ansible_collections/infinidat/infinibox && \
		python3 -m venv $(_venv) && \
		source $(_venv)/bin/activate && \
		python -m pip install --upgrade pip && \
		python -m pip install --upgrade --requirement $(_requirements_file)

test-sanity-locally: _setup-sanity-locally
	@# Run ansible sanity tests in accordance with
	@# https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#testing-collections
	@# This runs on an collection installed locally making it useful for dev and debugging.
	@# Not sure why, but ansible-test fails to discover py scripts to test.
	@# This specifies a "$test_file".
	cd $(_install_path_local)/ansible_collections/infinidat/infinibox && \
		source $(_venv)/bin/activate && \
		export test_file="plugins/modules/infini_map.py" && \
		echo -e "\n$$(date) - Sanity testing $$test_file\n" && \
		export ANSIBLE_LIBRARY="$(_install_path_local)/ansible_collections/infinidat/infinibox/plugins/modules:$$ANSIBLE_LIBRARY" && \
		export ANSIBLE_LIBRARY="$(_install_path_local)/ansible_collections/infinidat/infinibox/plugins/module_utils:$$ANSIBLE_LIBRARY" && \
		export ANSIBLE_LIBRARY="$(_install_path_local)/ansible_collections/infinidat/infinibox/plugins/filters:$$ANSIBLE_LIBRARY" && \
		ansible-test sanity --docker default -v "$$test_file"

test-sanity-locally-all: galaxy-collection-build-force galaxy-collection-install-locally test-sanity-locally
	@# Run local build, install and sanity test.
	@# Note that this will wipe $(_install_path_local).
	@echo "test-sanity-locally-all completed"

### IBox ###
infinishell:
	@infinishell --user $(_user) $(_ibox_url)

infinishell-events:
	@TERM=xterm echo "Command: event.watch username=$(_user) exclude=USER_LOGGED_OUT,USER_LOGIN_SUCCESS,USER_SESSION_EXPIRED,USER_LOGIN_FAILURE tail_length=35"
	@TERM=xterm infinishell --user $(_user) $(_ibox_url)

