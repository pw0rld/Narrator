
/* Copyright (c) 2021 SUSTech University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "configuration.h"
#include "host/network/misc.h"
#include <boost/algorithm/string.hpp>
using namespace boost;
/**********Used Paramters*******************/
// The number of SEs
uint32_t MAX_PEERS = 20;
// Expected mine time
uint32_t EXPECTED_ATTESTTAION_WAIT_TIME_IN_MILLISECONDS = 0;
// MAX atteatation times with each SE
uint32_t MAX_ATTESTATION_TIMES = 5;

// Print Attestation Info
uint32_t PRINT_ATTESTATION_MESSAGES = 0;
uint32_t PRINT_WARNNING_MESSAGES = 1;
uint32_t PRINT_INTERRUPT_MESSAGES = 1;
// HDD
uint32_t WRITE_BLOCKS_TO_HDD = 0;
uint32_t WRITE_SESSIONS_TO_HDD = 0;
uint32_t WRITE_HASH_TO_HDD = 0;
//
uint32_t PRINT_SENDING_MESSAGES = 1;
uint32_t PRINT_RECEIVING_MESSAGES = 1;
uint32_t PRINT_PEER_CONNECTION_MESSAGES = 1;
uint32_t PRINT_TRANSMISSION_ERRORS = 0;

/**********Unused Paramters*******************/
// NETWORK
uint32_t CONNECT_TO_PEERS_MILLISECONDS = 10000;
uint32_t RUN_NETWORK_EACH_MILLISECONDS = 20;

// Stop the miner even after receiving a block
uint32_t CAN_INTERRUPT = 0;
uint32_t REJECT_CONNECTIONS_FROM_UNKNOWNS = 1;
uint32_t PING_MIN_WAIT = 5;
uint32_t PING_MAX_WAIT = 10;
uint32_t PING_REPEAT = 1000;
uint32_t NO_DISCARD_LOCAL = 6;
uint32_t T_DISCARD[6] = {6};

set<string> KNOWN_VARS = {
	"MAX_PEERS",
	"EXPECTED_ATTESTTAION_WAIT_TIME_IN_MILLISECONDS",
	"MAX_ATTESTATION_TIMES",
	"PRINT_ATTESTATION_MESSAGES",
	"PRINT_WARNNING_MESSAGES",
	"PRINT_INTERRUPT_MESSAGES",
	"CONNECT_TO_PEERS_MILLISECONDS",
	"RUN_NETWORK_EACH_MILLISECONDS",
	"WRITE_BLOCKS_TO_HDD",
	"WRITE_SESSIONS_TO_HDD",
	"WRITE_HASH_TO_HDD",
	"PRINT_SENDING_MESSAGES",
	"PRINT_RECEIVING_MESSAGES",
	"PRINT_PEER_CONNECTION_MESSAGES",
	"PRINT_TRANSMISSION_ERRORS",
	"CAN_INTERRUPT",
	"REJECT_CONNECTIONS_FROM_UNKNOWNS",
	"PING_MIN_WAIT",
	"PING_MAX_WAIT",
	"PING_REPEAT",
	"NO_DISCARD_LOCAL"};

void set_configuration(string filepath)
{
	cout << "file_path" << filepath.c_str() << endl;
	ifstream infile(filepath.c_str());
	string l;
	while (getline(infile, l))
	{
		vector<std::string> sp = split(l, "=");
		if (sp.size() == 2)
		{
			trim(sp[0]);
			trim(sp[1]);
			string vname = sp[0];
			bool converted = true;
			unsigned long vvalue = safe_stoull(sp[1], converted);
			if (!converted)
				continue;

			if (KNOWN_VARS.find(vname) == KNOWN_VARS.end())
				continue;

			printf("\t ::: %s = %ld\n", vname.c_str(), vvalue);

			if (vname == "MAX_PEERS")
				MAX_PEERS = vvalue;
			else if (vname == "MAX_ATTESTATION_TIMES")
				MAX_ATTESTATION_TIMES = vvalue;
			else if (vname == "EXPECTED_ATTESTTAION_WAIT_TIME_IN_MILLISECONDS")
				EXPECTED_ATTESTTAION_WAIT_TIME_IN_MILLISECONDS = vvalue;
			else if (vname == "PRINT_ATTESTATION_MESSAGES")
				PRINT_ATTESTATION_MESSAGES = vvalue;
			else if (vname == "PRINT_WARNNING_MESSAGES")
				PRINT_WARNNING_MESSAGES = vvalue;
			else if (vname == "PRINT_INTERRUPT_MESSAGES")
				PRINT_INTERRUPT_MESSAGES = vvalue;
			else if (vname == "CONNECT_TO_PEERS_MILLISECONDS")
				CONNECT_TO_PEERS_MILLISECONDS = vvalue;
			else if (vname == "RUN_NETWORK_EACH_MILLISECONDS")
				RUN_NETWORK_EACH_MILLISECONDS = vvalue;
			else if (vname == "WRITE_BLOCKS_TO_HDD")
				WRITE_BLOCKS_TO_HDD = vvalue;
			else if (vname == "WRITE_SESSIONS_TO_HDD")
				WRITE_SESSIONS_TO_HDD = vvalue;
			else if (vname == "WRITE_HASH_TO_HDD")
				WRITE_HASH_TO_HDD = vvalue;
			else if (vname == "PRINT_SENDING_MESSAGES")
				PRINT_SENDING_MESSAGES = vvalue;
			else if (vname == "PRINT_RECEIVING_MESSAGES")
				PRINT_RECEIVING_MESSAGES = vvalue;
			else if (vname == "PRINT_PEER_CONNECTION_MESSAGES")
				PRINT_PEER_CONNECTION_MESSAGES = vvalue;
			else if (vname == "PRINT_TRANSMISSION_ERRORS")
				PRINT_TRANSMISSION_ERRORS = vvalue;
			else if (vname == "CAN_INTERRUPT")
				CAN_INTERRUPT = vvalue;
			else if (vname == "REJECT_CONNECTIONS_FROM_UNKNOWNS")
				REJECT_CONNECTIONS_FROM_UNKNOWNS = vvalue;
			else if (vname == "PING_MIN_WAIT")
				PING_MIN_WAIT = vvalue;
			else if (vname == "PING_MAX_WAIT")
				PING_MAX_WAIT = vvalue;
			else if (vname == "PING_REPEAT")
				PING_REPEAT = vvalue;
			else if (vname == "NO_DISCARD_LOCAL")
				NO_DISCARD_LOCAL = vvalue;
			else
			{
				printf("\t[-]Cannot find appropriate for %s\n", vname.c_str());
			}
		}
	}
	infile.close();
}
