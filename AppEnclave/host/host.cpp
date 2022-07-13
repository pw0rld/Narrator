
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
#include "state_requests.h"
#include "network/MyServer.hpp"
#include "network/get_ip.h"
#include "network/misc.h"
#include "enclave_operation.h"
#include "params.h"

using boost::asio::ip::tcp;
using namespace std;
using namespace std::chrono;

string my_ip="badip";
uint32_t my_port;
mt19937 rng;
unsigned long time_of_start;
boost::thread *mythread;
tcp_server *ser=NULL;
oe_enclave_t* cl_enclave = NULL;
bool is_system_init = false; 

// Input parmarers: argv1  enclave path; argv2 IP port; argv3 peer config; argv4 public ip addr; argv5 private ip addr
int main(int argc, const char* argv[]){

    //create enclave from path
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG; 
    cl_enclave = create_enclave(argv[1], flags);

    //Get my ip and port and setup server 
    //TODO: remove 
    //string ip = get_my_local_ip();
    //my_ip = ip;
    uint32_t port = atoi(argv[2]);
    my_port = port;
    string some_ip = string(argv[3]);
    if( split(some_ip,".").size() == 4 ){
        my_ip = some_ip;
        cout << "[+] Provided public ip and port: (" <<my_ip << ":" << port << ")." << endl;
    }
    
    //setup the server sevice
    boost::asio::io_service io_service;
    tcp_server server(io_service, my_ip, my_port);
    ser = &server;    
    
    Peer pr;
    pr.port = atoi(argv[4]);
    some_ip = string(argv[5]);
    if( split(some_ip,".").size() == 4 ){
        pr.ip = some_ip;
        cout << "[+] Provided server's ip and port: (" << pr.ip << ":" << pr.port << ")." << endl;
    }
    pr.connected = false;
    server.add_peer(pr, false );


    //The thread to init system
    boost::thread t1(system_init);
    mythread = &t1;

    //The thread to generate requests
    boost::thread t2(state_requests);
    mythread = &t2;

    //Start the server
    server.run_network();
    time_of_start = std::chrono::system_clock::now().time_since_epoch() /  std::chrono::milliseconds(1);
    io_service.run();
    

    pause();
exit:
    printf("Host: Terminating enclaves\n");
    if (cl_enclave)
        terminate_enclave(cl_enclave);
}
