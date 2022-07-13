#ifndef PARAMS_H
#define PARAMS_H

#include <iostream>
#include <string>


// Max number of chains
// The actual number of chains is specified in CHAINS
#define MAX_CHAINS (8*1024)


// Folder&file names
#define FOLDER_SEAL "../host/network/_Seal"
#define FOLDER_SESSIONS "../host/network/_Sessions"
#define FOLDER_PINGS "../host/network/_Pings"
#define FILE_CONFIGURATION	"../host/_configuration"
#define FILE_PEER_IPS	"../host/network/_peer_ip_allowed"
#define FILE_SEAL_STATE	"./_ae_state"

/***************Used Parameters***********/
/*
 * All of the below values can be set before runtime (no need to compile!!!) in the file "configuration", by
 * [VARIABLE_NAME],[VARIABLE_VALUE]
 */
extern uint32_t MAX_PEERS;

// Expected mine time
extern uint32_t EXPECTED_ATTESTTAION_WAIT_TIME_IN_MILLISECONDS;
// MAX atteatation times with each SE
extern uint32_t MAX_ATTESTATION_TIMES;
// Remote attestation debug Printing; 
extern uint32_t PRINT_ATTESTATION_MESSAGES;

// WarnNing debug Printing; 
extern uint32_t PRINT_WARNNING_MESSAGES;


// Logic state Printing;
extern uint32_t PRINT_SENDING_MESSAGES;
extern uint32_t PRINT_RECEIVING_MESSAGES;
extern uint32_t PRINT_INTERRUPT_MESSAGES;
extern uint32_t PRINT_PEER_CONNECTION_MESSAGES;
extern uint32_t PRINT_TRANSMISSION_ERRORS;


// Expected mine time
extern uint32_t EXPECTED_MINE_TIME_IN_MILLISECONDS;
//#define EXPECTED_MINE_TIME_IN_MILLISECONDS ( COEFF * 0.25 * 1000)

// NETWORK
extern uint32_t CONNECT_TO_PEERS_MILLISECONDS;
extern uint32_t RUN_NETWORK_EACH_MILLISECONDS;
extern uint32_t PING_MIN_WAIT;
extern uint32_t PING_MAX_WAIT;
extern uint32_t PING_REPEAT;

// HDD 
extern uint32_t WRITE_BLOCKS_TO_HDD;
extern uint32_t WRITE_SESSIONS_TO_HDD;
extern uint32_t WRITE_HASH_TO_HDD;


// Stop the miner even after receiving a block
extern uint32_t CAN_INTERRUPT;

//
extern uint32_t REJECT_CONNECTIONS_FROM_UNKNOWNS;


#define NO_T_DISCARDS 1
extern uint32_t T_DISCARD[NO_T_DISCARDS];

#endif
