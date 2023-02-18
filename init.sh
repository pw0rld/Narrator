#! /bin/bash
# Ubuntu 20
sudo apt-get update
sudo apt-get -y install ncdu micro ccache wget tmux zsh nload

echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -


sudo apt-get update
sudo apt-get -y install libboost-all-dev doxygen
sudo apt-get -y install clang-10 libssl-dev gdb libsgx-enclave-common libsgx-quote-ex libprotobuf17 libsgx-dcap-ql libsgx-dcap-ql-dev python3-pip libsqlite3-dev
sudo pip3 install cmake

# The following three apt-get commands are extracted from 

# openenclave_0.17.0/scripts/ansible/oe-contributors-setup.yml
sudo apt-get -y install curl make ninja-build shellcheck gcc g++ gdb libssl-dev openssl pkg-config apt-transport-https autoconf graphviz libexpat1-dev libtool subversion libcurl4-openssl-dev libncurses5-dev clang-10 clang-format-10 unzip python lldb-10
sudo apt-get -y install libsgx-enclave-common libsgx-ae-qve libsgx-ae-pce libsgx-ae-qe3 libsgx-qe3-logic libsgx-pce-logic
sudo apt-get -y install libx11-dev
sudo apt-get -y install libsgx-dcap-ql libsgx-dcap-ql-dev libsgx-urts libsgx-quote-ex sgx-aesm-service libsgx-aesm-ecdsa-plugin libsgx-aesm-pce-plugin libsgx-aesm-quote-ex-plugin

# For DCAP remote attestation
sudo apt-get -y install libsgx-dcap-default-qpl
sudo ln -s /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1.13.102.3 /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so
sudo cp ../config/sgx_default_qcnl.conf /etc/

sudo apt-get -y install libgflags-dev

sudo apt-get -y install dkms
wget https://download.01.org/intel-sgx/sgx-linux/2.14/distro/ubuntu20.04-server/sgx_linux_x64_driver_1.41.bin -O sgx_linux_x64_driver.bin
chmod +x sgx_linux_x64_driver.bin
sudo ./sgx_linux_x64_driver.bin

token=$(curl -s -X PUT -H "X-aliyun-ecs-metadata-token-ttl-seconds: 5" "http://100.100.100.200/latest/api/token")
region_id=$(curl -s -H "X-aliyun-ecs-metadata-token: $token" http://100.100.100.200/latest/meta-data/region-id)

# 配置PCCS_URL指向实例所在Region的PCCS
PCCS_URL=https://sgx-dcap-server-vpc.${region_id}.aliyuncs.com/sgx/certification/v3/
cat > /etc/sgx_default_qcnl.conf << EOF
# PCCS server address
PCCS_URL=${PCCS_URL}
# To accept insecure HTTPS cert, set this option to FALSE
USE_SECURE_CERT=TRUE
EOF

#./write_hosts.sh
#reboot
