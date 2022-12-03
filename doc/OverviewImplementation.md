### System Initialization
In this procedure, we utilize [Tendermint](https://tendermint.com/) as a BFT-based blockchain platform interact with all SEs autonomously. There is only one legitimate group of n SEs with known identities running on n different SGX-enabled platforms. Master SE is elected by group of n SEs by using distributed system consensus, and Slave SE is other SE instead of Master SE. 

The protocol flow figure is shown in [sys_init.png](./figure/sys_init.png), with the building process details as follows. 

```
Master SE ---------->  remote evidence ----------> Slave SE
Master SE <----------  remote evidence <---------- Slave SE
Master SE ---------->  AES pk and nonce ---------> Slave SE
Master SE <----------  AES        reply <--------- Slave SE
Master SE ---------->  Singed PKI certificate ---> Slave SE
Master SE <----------  PKI certificate key <------ Slave SE
Slave & Master SE ---> Init Messgae -------------> Tendermint
Slave & Master SE <--- Reply messgae <------------ Tendermint
Slave & Master SE System Init Done
```

First, Master SE will generate RSA public key with a remote attestation message and send this evidence to all peers. Peers will verify the master's evidence and return evidence. The master also will verify, then the master will genc only as key as the PKI key to encrypt secrets and broadcast all peers. If finished, the master will record this init message to the Tendermint. 

By building functions `write_tendermint()` and `read_and_verify_tendermint()`, we implement $\mathrm{Blockchain.write} (\mathrm{ID} , <key, blob>)\rightarrow \sigma$ and $\mathrm{Blockchain.read} (\mathrm{ID} , key) \rightarrow (blob, \sigma)$, respectively. The $ID+key$ and $blob$ correspond to variables `sgx_pulickey` and `sgx_blob`, severally.

`/ServerEnclave/host/system_init.cpp` contains the code for the SE initialization process, in which some codes are also reused in `/AppEnclave`. In `/host/network/`, there are several configurations for secure communication channel from both the `/AppEnclave` and the `/ServerEnclave`. 


### State Update
In this procedure, we utilize $Echo\ Broadcast$'s variants as communication protocol to implement State Update. After State Initialization, the target SE is ready to process AEs’ state update requests.

The protocol flow figure is shown in [state_update.png](./figure/state_update.png), with the building process details as follows. 

```
AE       ---------->  local evidence ----------> local SE 
AE       <----------  local evidence <---------- local SE
AE       ---------->  State Update   ----------> local SE 
local SE ---------->  Prepare State  ----------> SEs 
local SE <----------  f+1 ACKs       <---------- SEs 
local SE ---------->  exeute & update ---------->AE 
AE finish a State Update
```
TODO: A paragraph describing the above process like System Initialization.

AE's communication code is included in `AppEnclave/host/system_init.cpp`, local SE's communicate code is implemented in `ServerEnclave/host/system_init.cpp`, similarly. Code of process request betwen SEs is in `ServerEnclave/host/network/process_buffer.cpp`.

As for exeute condition, upon receive `ser->Re_Peers.size() / 2 + 1` quorum amount, state of local SE exeute & update to AE whose code included in `AppEnclave/host/network/process_buffer.cpp`

In addition, $new\ inputs$ is implemented by function `state_requests()`, and $response()$ correspond code `else if (sp[0] == "#AE_Return_Final` in `AppEnclave/host/network/process_buffer.cpp` which means writing state to disk.

### State Read

When an AE wants to check the freshness of its state or the sealed data from OS, it calls the function $readState()$ to obtain the latest state digests from the target SE.

The difference between State Read and Update means `read state from disk to memeory` and `write state from memeory to disk`. To read the state to Enclave memeory, use fuction `load_application_state()`.

The protocol flow figure is shown in [state_read.png](./figure/state_read.png), with the building process details as follows. 

```
AE       ---------->  local evidence ----------> local SE 
AE       <----------  local evidence <---------- local SE
AE       ---------->  State Read     ----------> local SE 
local SE ---------->  Prepare State  ---------->  SEs 
local SE <----------  f+1 ACKs        <---------- SEs 
local SE ---------->  exeute & update  ---------->  AE 
AE finish a State Read
```

TODO: A paragraph describing the above process like System Initialization.
### Restart Protocol

TODO