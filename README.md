# Narrator: Secure and Practical State Continuity for Trusted Execution on Cloud
Narrator is a demo which based Intel SGX to explanation our paper.

## Architecture

TODO



## Requirements:

Dependent on the SGX environment, real machines that can meet the SGX environment are required.

### Boost C++
```bash
sudo apt-get install libboost-all-dev
```

### DCAP Driver install

```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main" | sudo tee /etc/apt/sources.list.d/llvm-toolchain-focal-10.list
wget -qO - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
sudo apt update

sudo apt -y install dkms
proxychains wget https://download.01.org/intel-sgx/sgx-linux/2.15/distro/ubuntu20.04-server/sgx_linux_x64_driver_1.41.bin -O sgx_linux_x64_driver.bin
chmod +x sgx_linux_x64_driver.bin
sudo ./sgx_linux_x64_driver.bin
```

Check successful of install:

```bash
pw0rld@pw0rld-code:~/Desktop/build$ dmesg | grep -i sgx
[ 2199.851152] intel_sgx: loading out-of-tree module taints kernel.
[ 2199.851186] intel_sgx: module verification failed: signature and/or required key missing - tainting kernel
[ 2199.851857] intel_sgx: EPC section 0x90200000-0x95ffffff
[ 2199.852119] intel_sgx: Intel SGX DCAP Driver v1.41
```

## Attestation DHCP: 

In our project, we use DHCP with version 1.8x

```bash
wget https://deb.nodesource.com/setup_14.x
sudo chmod +x setup_14.x
sudo ./setup_14.x
sudo apt-get install -y nodejs

wget https://download.01.org/intel-sgx/sgx-dcap/1.8/linux/distro/ubuntu18.04-server/debian_pkgs/libs/libsgx-dcap-default-qpl/libsgx-dcap-default-qpl_1.8.100.2-bionic1_amd64.deb
sudo dpkg -i libsgx-dcap-default-qpl_1.8.100.2-bionic1_amd64.deb
dpkg --listfiles libsgx-dcap-default-qpl
cd /usr/lib/x86_64-linux-gnu/
sudo ln -s libdcap_quoteprov.so.1.8.100.2 libdcap_quoteprov.so

wget https://github.com/intel/SGXDataCenterAttestationPrimitives/archive/refs/tags/DCAP_1.8.zip
unzip DCAP_1.8.zip

cd ./SGXDataCenterAttestationPrimitives-DCAP_1.8/tools/PCKCertSelection
sudo make -j
mkdir ../../QuoteGeneration/pccs/lib
sudo cp ./out/libPCKCertSelection.so ../../QuoteGeneration/pccs/lib/
cd ../../QuoteGeneration/installer/linux/deb/sgx-dcap-pccs/
sudo apt install debhelper
sudo ./build.sh
sudo dpkg -i sgx-dcap-pccs_1.8.100.2-focal1_amd64.deb
```

Then your should register the [Intel® SGX Services for ECDSA Attestation](https://api.portal.trustedservices.intel.com/) 
and input your PCS API Key in `/opt/intel/sgx-dcap-pccs/config/default.json`

Noteworthy, in your Local Network, there has only dhcp service needs to exit.

Peers can modify `/etc/sgx_default_qcnl.conf` to use the dhcp server

Test for dhcp server working
```bash
curl --noproxy "*" -v -k -G "https://127.0.0.1:8081/sgx/certification/v2/rootcacrl"
    
 
* Connection #0 to host 127.0.0.1 left intact
308201203081c8020101300a06082a8648ce3d0403023068311a301806035504030c11496e74656c2053475820526f6f74204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553170d3231303432363133333734375a170d3232303432363133333734375aa02f302d300a0603551d140403020101301f0603551d2304183016801422650cd65a9d3489f383b49552bf501b392706ac300a06082a8648ce3d0403020347003044022074a8ed641048cf06b35d93237f9eb6966f28b0d71cffc58e9ec9ba7aa23f322302203e7dd2926e78d309d2e4a7fab56b066e4d509b11a3ed2e9b15

sudo PM2_HOME=/opt/intel/sgx-dcap-pccs/.pm2/ pm2  restart pccs
```
More information about DHCP Server:
https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/SGX_QuoteEx_Integration.md
https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Contributors/NonAccMachineSGXLinuxGettingStarted.md
https://api.portal.trustedservices.intel.com/provisioning-certification


## openenclave SDK install

```bash
sudo apt -y install clang-10 libssl-dev gdb libsgx-enclave-common libsgx-quote-ex libprotobuf17 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client libsqlite3-dev
sudo apt-get install python3-pip
sudo pip3 install cmake
sudo apt install doxygen
sudo apt install git
#source build openenclave sdk
git clone --recursive --branch=v0.14.0  https://github.com/openenclave/openenclave.git 
cd openenclave
git submodule update --init --recursive 
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/openenclave_0_14 
sudo make && make install
source /opt/openenclave/share/openenclave/openenclaverc
```

## Tendermint build
```bash
cd tendermint-ansible
cd tendermint_core
make install_abci
make build
```
