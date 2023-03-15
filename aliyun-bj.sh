#! /bin/bash
workdir=$(cd $(dirname $0); pwd)
ssh_config="ssh -i $workdir/../aliyun_key/narrator-bj.pem" #Here is your machine's ssh keypair
cluster_size=5
index=0


client_ip="eng_client"
narrator_folder_name="Narrator"
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
    time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/AE1.log /tmp/AE1.log
    time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/AE2.log /tmp/AE2.log
   time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/AE3.log /tmp/AE3.log
   time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/AE4.log /tmp/AE4.log
   time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/AE5.log /tmp/AE5.log
   time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/AE6.log /tmp/AE6.log
    # time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/SE.log /tmp/SE.log
    # time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/SE1.log /tmp/SE1.log
    # time rsync -a -e "$ssh_config" root@${cloud_ip}:/tmp/SE2.log /tmp/SE2.log
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
        rm ~/Narrator -rf;
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
123.56.73.249
112.124.17.142
127.0.0.1
EOF
    "
    echo "Write _peers"
    $ssh_config root@${cloud_ip} "
sudo cat <<EOF>>~/Narrator/ServerEnclave/host/network/_peers
123.56.73.249:3389:1:se_master
123.56.73.249:3388:2:se_slave
112.124.17.142:3389:11:se_slave
112.124.17.142:3388:12:se_slave
127.0.0.1:8707:29:client
127.0.0.1:8706:28:client
127.0.0.1:8705:27:client
127.0.0.1:8704:26:client
127.0.0.1:8703:25:client
127.0.0.1:8702:24:client
EOF
    "
    echo "Finish!!!"
}
# cd ~/Narrator/ServerEnclave/build/
# ~/Narrator/ServerEnclave/build/host/attestation_host ~/Narrator/ServerEnclave/build/enclave/enclave_a.signed 3386 ~/Narrator/ServerEnclave/host/network/_peers 172.25.164.22
# ~/Narrator/AppEnclave/build/host/attestation_host ~/Narrator/AppEnclave/build/enclave/enclave_a.signed 8707 127.0.0.1 3389 172.25.164.21>> /tmp/AE.log
run_narrator_serverenclave() {
    cloud_ip=$1
    echo "Shudown Narrator"
    $ssh_config root@${cloud_ip} "
    ps -ef | grep attestation | grep -v grep | awk '{print \$2}' |sudo xargs kill -9
    sleep 1
    "
    echo "Running ServerEnclave to ${cloud_ip}"
    $ssh_config root@${cloud_ip} "
    cd ~/$narrator_folder_name/ServerEnclave/build;
    # nohup ./host/attestation_host ./enclave/enclave_a.signed 3389 ../host/network/_peers \$(hostname -I) &
    # sleep 1
    # nohup ./host/attestation_host ./enclave/enclave_a.signed 3388 ../host/network/_peers \$(hostname -I) >> /tmp/SE1.log 2>&1 &
    # sleep 1
    # nohup ./host/attestation_host ./enclave/enclave_a.signed 3387 ../host/network/_peers \$(hostname -I) >> /tmp/SE2log 2>&1 &  
    # sleep 1
    # nohup ./host/attestation_host ./enclave/enclave_a.signed 3386 ../host/network/_peers \$(hostname -I) >> /tmp/SE3log 2>&1 &  
    # sleep 1
    # Wlan
    nohup ./host/attestation_host ./enclave/enclave_a.signed 3389 ../host/network/_peers 123.56.73.249 &  
    sleep 1
    nohup ./host/attestation_host ./enclave/enclave_a.signed 3388 ../host/network/_peers 123.56.73.249 >> /tmp/SE1log 2>&1 & 
    sleep 1
    #nohup ./host/attestation_host ./enclave/enclave_a.signed 3387 ../host/network/_peers 123.56.73.249 >> /tmp/SE2log 2>&1 & 
    sleep 1
    #nohup ./host/attestation_host ./enclave/enclave_a.signed 3386 ../host/network/_peers 123.56.73.249 >> /tmp/SE3log 2>&1 & 
    sleep 1
    #nohup ./host/attestation_host ./enclave/enclave_a.signed 3385 ../host/network/_peers 123.56.73.249 >> /tmp/SE4log 2>&1 & 
    sleep 1
    #nohup ./host/attestation_host ./enclave/enclave_a.signed 3384 ../host/network/_peers 123.56.73.249 >> /tmp/SE5log 2>&1 & 
    "
}


run_narrator_appenclave() {
    cloud_ip=$1
    echo "Running Appenclave to ${cloud_ip}"
    $ssh_config root@${cloud_ip} "
        cd ~/$narrator_folder_name/AppEnclave/build;
        rm /tmp/AE*  2>&1;
        # nohup ./host/attestation_host ./enclave/enclave_a.signed 8707 127.0.0.1 3389 \$(hostname -I) >> /tmp/AE.log 2>&1 & 
        # wlan
        nohup ./host/attestation_host ./enclave/enclave_a.signed 8707 127.0.0.1 3389 123.56.73.249 >> /tmp/AE1.log 2>&1 & 
        nohup ./host/attestation_host ./enclave/enclave_a.signed 8706 127.0.0.1 3389 123.56.73.249 >> /tmp/AE2.log 2>&1 & 
        nohup ./host/attestation_host ./enclave/enclave_a.signed 8705 127.0.0.1 3389 123.56.73.249 >> /tmp/AE3.log 2>&1 & 
        nohup ./host/attestation_host ./enclave/enclave_a.signed 8704 127.0.0.1 3389 123.56.73.249 >> /tmp/AE4.log 2>&1 & 
        nohup ./host/attestation_host ./enclave/enclave_a.signed 8703 127.0.0.1 3389 123.56.73.249 >> /tmp/AE5.log 2>&1 & 
        nohup ./host/attestation_host ./enclave/enclave_a.signed 8702 127.0.0.1 3389 123.56.73.249 >> /tmp/AE6.log 2>&1 & 

        "
}

build_narrator(){
    cloud_ip=$1
    echo "Build Narrator ServerEnclave"
    $ssh_config root@${cloud_ip} "
        cd ~/Narrator/ServerEnclave/;
        git reset --hard;
        git pull;
        rm -rf build;
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
elif [ "$2" == "log" ]
then
    echo "Fetch the remote log"
    download_log $1
# elif [ "$2" == "Tendermint" ]
# then
#     # TODO
elif [ "$2" == "Update" ]
then
    echo "Update the Serverenclave";
    # build_narrator $1
    write_conf $1
    run_narrator_serverenclave $1
elif [ "$2" == "Appenclave" ]
then
    echo "Setup the Appenclave";
    run_narrator_appenclave $1
elif [ "$2" == "Appenclave" ]
then
    echo "Kill all!!";
    $ssh_config root@${1} "
    ps -ef | grep attestation | grep -v grep | awk '{print \$2}' |sudo xargs kill -9
    sleep 1
    "
fi
# send_oe_sdk $1
# send_cloud_config $1
# install_oe_sdk $1
# build_narrator_local
# send_narrator $1
# run_narrator_serverenclave $1