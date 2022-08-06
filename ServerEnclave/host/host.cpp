
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

#include <ctime>
#include <iostream>
#include <string>
#include <list>
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <vector>
#include <random>
#include "system_init.h"
#include "secure_channel.h"
#include "network/MyServer.hpp"
#include "network/get_ip.h"
#include "configuration.h"
#include "network/misc.h"
#include "enclave_operation.h"
#include "params.h"

using boost::asio::ip::tcp;
using namespace std;
using namespace std::chrono;

string my_ip = "badip";
uint32_t my_port;
mt19937 rng;
unsigned long time_of_start;
boost::thread *mythread;
tcp_server *ser = NULL;
oe_enclave_t *se_enclave = NULL;
string my_role = "norole";

// Input parmarers: argv1  enclave path; argv2 IP port; argv3 peer config; argv4 public ip addr; argv5 private ip addr
int main(int argc, const char *argv[])
{
    // create enclave from path
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    se_enclave = create_enclave(argv[1], flags);

    // Set the configuration from a file
    string config_file = string(FILE_CONFIGURATION);
    cout << "[+] Set configuration from " << config_file << endl;

    set_configuration(config_file);

    // Get my ip and port and setup server
    string ip = get_my_local_ip();
    uint32_t port = atoi(argv[2]);
    my_ip = ip;
    my_port = port;

    // If fifth argument is provided, then it is the public IP
    if (argc >= 5)
    {
        string some_ip = string(argv[4]);
        if (split(some_ip, ".").size() == 4)
        {
            ip = my_ip = some_ip;
            cout << "[+] Provided public ip:" << my_ip << endl;
        }
    }

    // setup the server sevice
    boost::asio::io_service io_service;
    tcp_server server(io_service, ip, atoi(argv[2]));
    ser = &server;

    // If sixth argument is provided, then it is the private IP
    string private_ip = "";
    if (argc >= 6)
    {
        string some_ip = string(argv[5]);
        if (split(some_ip, ".").size() == 4)
        {
            private_ip = some_ip;
            cout << "[+] Provided private ip:" << private_ip << ":" << endl;
        }
    }

    // Reading the Peers' IP configuration
    ifstream infile(argv[3]);
    string l;
    cout << "[+] Adding peers from " << argv[3] << endl;
    std::vector<Peers> tmp;
    while (getline(infile, l))
    {
        int p = l.find(":");
        int p1 = l.find(":", p + 1);
        int p2 = l.find(":", p1 + 1);
        if (p > 0)
        {
            Peer pr;
            pr.ip = l.substr(0, p);
            pr.port = atoi(l.substr(p + 1, p1).c_str());
            pr.uuid = atoi(l.substr(p1 + 1, p2).c_str());
            pr.role = l.substr(p2 + 1, l.length());
            pr.waiting_count = 0; // waiting time for each state
            pr.attestState = 0;   // peer attestatted state
            if (pr.ip != my_ip && pr.ip != private_ip || pr.port != port)
            {
                if ((my_role == "se_master") || (pr.role != "client"))
                {
                    tmp.push_back(pr);
                }
            }
            else
            {
                my_role = pr.role;
                set_uuid_ecall(se_enclave, pr.uuid);
            }
        }
    }
    infile.close();
    int tr = 0;
    while (tr < 10000 && tmp.size() > 0 && server.no_peers() < MAX_PEERS)
    {
        int t = rng() % tmp.size();
        if (tmp[t].ip != my_ip || tmp[t].port != port)
        {
            server.add_peer(tmp[t], false);
            tmp.erase(tmp.begin() + t);
        }
    }
    server.print_peers();

    // Load allowed IP for connecting peers
    if (REJECT_CONNECTIONS_FROM_UNKNOWNS)
    {
        ifstream infile2(FILE_PEER_IPS);
        string l;
        cout << "[+] Adding IPs for connecting peers from " << FILE_PEER_IPS << endl;
        while (getline(infile2, l))
        {
            string ip = string(l);
            boost::trim(ip);
            vector<std::string> sp = split(ip, ".");
            if (sp.size() == 4)
            {
                server.add_peers_ip(ip);
                cout << "Add ::" << ip << "::" << endl;
            }
        }
        infile2.close();
    }

    bool isSystemSetup = false;
    // read previously sealed configuration info; if system has already intilized, skip the pki setup and blockchain checking phase

    if (isSystemSetup == false)
    {
        // If system hasn't initialized previously and the SE's role is master, start an system initialization thread
        if (my_role.compare("se_master") == 0)
        {
            boost::thread t1(system_init);
            mythread = &t1;
        }
    }
    else
    {
        // initilize secure communication channel
        boost::thread t1(secure_channel);
        mythread = &t1;
    }
    // Start the server
    server.Re_piplines_vector.reserve(sizeof(Re_piplines) * 1000);
    server.run_network();
    time_of_start = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
    io_service.run();

exit:
    printf("Host: Terminating enclaves\n");
    if (se_enclave)
        terminate_enclave(se_enclave);
}
