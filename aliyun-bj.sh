#! /bin/bash
workdir=$(cd $(dirname $0); pwd)
ssh_config="ssh -i $workdir/../aliyun_key/narrator-bj.pem" #Here is your machine's ssh keypair
cluster_size=5
index=0


client_ip="eng_client"
narrator_folder_name="narrator"
engraft_folder_name="engraft"
raft_cli_folder_name="raft_client"
damysus_folder_name="damysus"


build_narrator_local(){
    echo "sending SeverEnclave to ${cloud_ip}";
    cd $workdir/../example/ServerEnclave;
    rm ./build/ -rf;
    mkdir ./build;
    cd ./build;
    cmake ..;
    make -j;
    echo "sending AppEnclave to ${cloud_ip}";
    cd $workdir/../example/AppEnclave;
    rm ./build/ -rf;
    mkdir ./build;
    cd ./build;
    cmake ..;
    make -j;
}

send_narrator() {
    cloud_ip=$1
    echo "sending Narrator to ${cloud_ip}"
    time rsync -a -e "$ssh_config" \
    $workdir/../example/ \
    root@${cloud_ip}:~/${narrator_folder_name}/
}

download_log(){
    cloud_ip=$1
    echo "Download log ${cloud_ip}"
    time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/AE.log /tmp/AE.log
    time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/SE.log /tmp/SE.log
}

install_oe_sdk() {
    cloud_ip=$1
    $ssh_config root@${cloud_ip} "
        cd ~/aliyun_cloud_cntl/;
        chmod +x *;
        ./init_aliyun.sh;
    "
}

install_oe_sdk_back() {
    cloud_ip=$1
    $ssh_config root@${cloud_ip} "
        cd ~/aliyun_cloud_cntl/;
        chmod +x *;
        ./init_aliyun.sh;
        rm -rf ~/aliyun_oe_0.17.0/build;
        mkdir ~/aliyun_oe_0.17.0/build;
        cd ~/aliyun_oe_0.17.0/build;
        cmake .. -DCMAKE_INSTALL_PREFIX=/opt/openenclave_0_17;
        sudo make -j8 install;
    "
}

send_cloud_config() {
    cloud_ip=$1
    echo "sending cloud_config to ${cloud_ip}"
    time rsync -a -e "$ssh_config" \
    $workdir/../install_script/ \
    root@${cloud_ip}:~/aliyun_cloud_cntl/
}


Clone_Narrator() {
    cloud_ip=$1
    echo "git clone source to ${cloud_ip} $workdir"
    $ssh_config root@${cloud_ip} "
        cd ~/;
        # git clone https://github.com/pw0rld/Narrator.git;
        git clone https://gitee.com/pw0rld/Narrator.git;
        cd ~/Narrator;
        chmod +x init.sh;
        ./init.sh;
        cd ~/Narrator/openenclave17/;
        rm -rf ./build;
        mkdir ./build;
        cd ./build;
        cmake .. -DCMAKE_INSTALL_PREFIX=/opt/openenclave_0_17;
        sudo make -j8 install;
    "
}

Update_host_config(){
    cloud_ip=$1
    echo '''
    Add to /etc/hosts, this step inorder to speed up the access on github
    204.232.175.78 http://documentcloud.github.com
    207.97.227.239 http://github.com
    204.232.175.94 http://gist.github.com
    107.21.116.220 http://help.github.com
    207.97.227.252 http://nodeload.github.com
    199.27.76.130 http://raw.github.com
    107.22.3.110 http://status.github.com
    204.232.175.78 http://training.github.com
    207.97.227.243 http://www.github.com
    ''';
    $ssh_config root@${cloud_ip} "
sudo cat <<EOF>>/etc/hosts
    204.232.175.78 http://documentcloud.github.com
    207.97.227.239 http://github.com
    204.232.175.94 http://gist.github.com
    107.21.116.220 http://help.github.com
    207.97.227.252 http://nodeload.github.com
    199.27.76.130 http://raw.github.com
    107.22.3.110 http://status.github.com
    204.232.175.78 http://training.github.com
    207.97.227.243 http://www.github.com
EOF
    "
}

write_conf(){
    cloud_ip=$1
    echo "Clean current _peer_ip_allowed and _peers"
    $ssh_config root@${cloud_ip} "
rm ~/Narrator/ServerEnclave/host/network/_peer_ip_allowed;
rm ~/Narrator/ServerEnclave/host/network/_peers;
    "
    echo "Write _peer_ip_allowed"
    $ssh_config root@${cloud_ip} "
sudo cat <<EOF>>~/Narrator/ServerEnclave/host/network/_peer_ip_allowed
172.25.164.22
172.25.164.21
127.0.0.1
EOF
    "
    echo "Write _peers"
    $ssh_config root@${cloud_ip} "
sudo cat <<EOF>>~/Narrator/ServerEnclave/host/network/_peers
172.25.164.21:3389:1:se_master
172.25.164.21:3388:2:se_slave
172.25.164.22:3387:3:se_slave
172.25.164.22:3386:4:se_slave
127.0.0.1:8707:9:client
EOF
    "
    echo "Finish!!!"
}
# cd ~/Narrator/ServerEnclave/build/
# ~/Narrator/ServerEnclave/build/host/attestation_host ~/Narrator/ServerEnclave/build/enclave/enclave_a.signed 3386 ~/Narrator/ServerEnclave/host/network/_peers 172.25.164.22
# ~/Narrator/AppEnclave/build/host/attestation_host ~/Narrator/AppEnclave/build/enclave/enclave_a.signed 8707 127.0.0.1 3389 172.25.164.19>> /tmp/AE.log
run_narrator_serverenclave() {
    cloud_ip=$1
    echo "Shudown Narrator"
    $ssh_config root@${cloud_ip} "ps -ef | grep attestation | grep -v grep | awk '{print \$2}' |sudo xargs kill -9"
    echo "Running ServerEnclave to ${cloud_ip}"
    $ssh_config root@${cloud_ip} "
    cd ~/ServerEnclave/build;
    ~/$narrator_folder_name/ServerEnclave/build/host/attestation_host ~/$narrator_folder_name/ServerEnclave/build/enclave/enclave_a.signed 8001 ~/$narrator_folder_name/ServerEnclave/host/network/_peers ${cloud_ip}
    " >> ServerEnclave.log
}


run_narrator_appenclave() {
    cloud_ip=$1
    echo "Running ServerEnclave to ${cloud_ip}"
    $ssh_config root@${cloud_ip} "~/$narrator_folder_name/ServerEnclave/build/host/attestation_host ~/$narrator_folder_name/ServerEnclave/build/enclave/enclave_a.signed 8003 ${cloud_ip} 8001 ${cloud_ip}" >> log.log
}

build_narrator(){
    cloud_ip=$1
    echo "Build Narrator ServerEnclave"
    $ssh_config root@${cloud_ip} "
        cd ~/Narrator/ServerEnclave/;
        mkdir build;
        cd build;
        cmake ..;
        make -j;
    "
    echo "Build Narrator ServerEnclave Successful! Now build the AppEnclave"
    $ssh_config root@${cloud_ip} "
        cd ~/Narrator/AppEnclave/;
        mkdir build;
        cd build;
        cmake ..;
        make -j;
    "
    echo "Finish!"
}


if [ "$2" == "install" ]
then
    echo "Install openenclave and Read for the requirement"
    Clone_Narrator $1
    write_conf $1
    build_narrator $1
elif [ "$2" == "fetchlog" ]
then
    echo "Fetch the remote log"
    download_log $1
# elif [ "$2" == "Tendermint" ]
# then
#     # TODO
elif [ "$2" == "Serverenclave" ]
then
    echo "Setup the Serverenclave";
    run_narrator_serverenclave $1
elif [ "$2" == "Appenclave" ]
then
    echo "Setup the Appenclave";
    run_narrator_appenclave $1
fi
# send_oe_sdk $1
# send_cloud_config $1
# install_oe_sdk $1
# build_narrator_local
# send_narrator $1
# run_narrator_serverenclave $1