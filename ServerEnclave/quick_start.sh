#!/bin/zsh


#Start tendermint
cd ./tendermint
make build_abci
make install_abci
cd ..


PROCESS=`ps -ef|grep abci-cli|grep -v grep|grep -v PPID|awk '{ print $2}'`

for i ($PROCESS) {
    echo "Clean pre programs abci and tendermint process and pid is\n $i"
    ps -ef | grep abci-cli | grep -v grep | awk '{print $2}' |sudo xargs kill -9
}

sleep 1s
# nohup abci-cli kvstore >> /dev/null &
# rm -rf ~/.tendermint
nohup tendermint start --proxy-app=kvstore >> /dev/null &
# nohup tendermint start >> /dev/null &
sleep 1s

if [ "$(curl -sL -w '%{http_code}' localhost:26657/status -o /dev/null)" = "200" ]; then

echo "Success"

else

echo "Tendermint Setup Fail. Then will kill"

PROCESS=`ps -ef|grep abci-cli|grep -v grep|grep -v PPID|awk '{ print $2}'`
for i ($PROCESS) {
    echo "Clean pre programs abci and tendermint process and pid is\n $i"
    ps -ef | grep abci-cli | grep -v grep | awk '{print $2}' |sudo xargs kill -9
}
fi

# PROCESS=`ps -ef|grep attestation|grep -v grep|grep -v PPID|awk '{ print $2}'`

# for i ($PROCESS) {
#     echo "Clean pre programs attestation process and pid is\n $i"
#     ps -ef | grep attestation | grep -v grep | awk '{print $2}' |sudo xargs kill -9
# }



# peer_array=(8002 8003)
# ip="192.168.1.107"
# for pi ($peer_array) {
#     echo "sudo nohup ./cmake-build-debug/host/attestation_host ./cmake-build-debug/enclave/enclave_a.signed $pi ./host/network/_peers $ip"
#     /bin/rm $pi.txt
#     nohup ./host/attestation_host ./enclave/enclave_a.signed $pi ../host/network/_peers $ip >> $pi.txt &
# }

# # local_array=(8002 8003)
# # ip="192.168.1.107"
# # for pi ($peer_array) {
# #     echo "sudo nohup ./host/attestation_host ./enclave/enclave_a.signed $pi ../host/network/_peers $ip"
# #     /bin/rm $pi.txt
# #     nohup ./host/attestation_host ./enclave/enclave_a.signed $pi ../host/network/_peers $ip >> $pi.txt &
# # }


# ./host/attestation_host ./enclave/enclave_a.signed 8093 10.16.55.3 8001 10.16.55.3