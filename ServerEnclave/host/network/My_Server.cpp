/*
Copyright (c) 2018, Ivica Nikolic <cube444@gmail.com>
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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
#include <fstream>
#include <string>
#include <list>
#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
#include <chrono>
#include <vector>
#include "My_Server.hpp"
#include "host/system_init.h"
#include "message_produce.h"
#include "process_buffer.h"

using boost::asio::ip::tcp;
using namespace std;

extern oe_enclave_t *se_enclave;
extern tcp_server *ser;
extern mt19937 rng;
// extern string my_ip;

std::mutex mtx;
string folder_sessions = string(FOLDER_SESSIONS);

/*
 * tcp_connection
 */
typedef boost::shared_ptr<tcp_connection> pointer;

pointer tcp_connection::create(boost::asio::io_service &io_service)
{
  return pointer(new tcp_connection(io_service));
}

tcp::socket &tcp_connection::socket()
{
  return socket_;
}

void tcp_connection::start()
{
  try
  {
    auto self(shared_from_this());
    socket_.async_read_some(boost::asio::buffer(data_buffer),
                            [this, self](boost::system::error_code ec, std::size_t length)
                            {
                              if (!ec)
                              {
                                for (int z = 0; z < length; z++)
                                {
                                  full_buffer.push_back(data_buffer[z]);
                                }
                                ser->add_bytes_received(length, 0);
                                fflush(stdout);
                                process_buffer(full_buffer, ser, se_enclave);
                                start();
                              }
                            });
  }
  catch (...)
  {
    cout << "[-]Async_read_some failed" << endl;
    fflush(stdout);
    exit(3);
  }
}

tcp_connection::tcp_connection(boost::asio::io_service &io_service)
    : socket_(io_service), full_buffer(""), id(0)
{
}

// tcp_server
tcp_server::tcp_server(boost::asio::io_service &io_service, string ip, uint32_t port)
    : acceptor_(io_service, tcp::endpoint(tcp::v4(), port)), my_ip(ip), my_port(port), t(new boost::asio::deadline_timer(io_service)), bytes_received(0), bytes_txs_received(0)
{
  start_accept();
  if (PING_REPEAT > 0)
  {
    no_pings = 0;
    unsigned long time_of_now = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
    next_ping = time_of_now + PING_MIN_WAIT + (rng() % (PING_MAX_WAIT - PING_MIN_WAIT));
  }
}

int tcp_server::no_peers()
{
  return peers.size();
}

int tcp_server::no_connected_peers()
{
  int count = 0;
  for (int i = 0; i < peers.size(); i++)
    count += peers[i].connected; // peers[i].session != NULL;
  return count;
}

void tcp_server::add_peer(Peer p, bool is_connected)
{
  if (!(p.ip == my_ip && p.port == my_port))
  {
    string key = p.ip + ":" + to_string(p.port);
    if (speers.find(key) != speers.end())
      return;
    if (!is_connected)
    {
      p.connected = false;
      p.session = NULL;
      p._strand = NULL;
    }
    peers.push_back(p);
    speers.insert(make_pair(key, 1));
  }
}

void tcp_server::add_indirect_peer_if_doesnt_exist(string p)
{
  if (speers.find(p) == speers.end())
  {
    int pos = p.find(":");
    if (pos > 0)
    {
      Peer pr;
      pr.ip = p.substr(0, pos);
      pr.port = atoi(p.substr(pos + 1, p.length()).c_str());
      add_peer(pr, false);
    }
  }
}

void tcp_server::add_peers_ip(string ip)
{
  peer_ips.insert(ip);
}

void tcp_server::close_peer_connection(uint32_t no)
{
  if (no >= peers.size())
    return;
  peers[no].session = NULL;
  peers[no].connected = false;
  peers[no]._strand = NULL;

  if (PRINT_PEER_CONNECTION_MESSAGES)
  {
    printf("\033[31;1mClosing connection to peer %s:%d\033[0m", (peers[no].ip).c_str(), peers[no].port);
    printf(" ::: #Connected peers : %d", no_connected_peers());
    printf("\n");
    fflush(stdout);
  }
}

void tcp_server::print_peers()
{
  cout << "[+]Here is Peers:" << endl;
  for (int i = 0; i < peers.size(); i++)
  {
    if (((peers[i].role).compare("se_master") == 0) || ((peers[i].role).compare("se_slave") == 0))
    {

      Re_Peers[i][peers[i].ip] = peers[i].port;
      cout << '\t' << (peers[i]).ip << " : " << peers[i].port << "   connected: " << peers[i].connected << "   Attested: " << to_string(peers[i].attestState) << endl;
    }
  }

  cout << "[+]Here is Clients:" << Re_Peers.size() << endl;
  for (int i = 0; i < peers.size(); i++)
  {
    if ((peers[i].role).compare("client") == 0)
    {
      cout << '\t' << (peers[i]).ip << " : " << peers[i].port << "   connected: " << peers[i].connected << "   Attested: " << to_string(peers[i].attestState) << endl;
    }
  }
}

void tcp_server::handle_write(boost::system::error_code ec, size_t length, int index)
{
  if (index >= peers.size() || peers[index]._m.size() <= 0)
    return;
  string mm = peers[index]._m[0];
  if (mm.find("#full_block") == 0 and mm.length() > 10)
  {
    string mz = mm.substr(mm.length() - 14, 13);
    bool pr = true;
    unsigned long sol = safe_stoull(mz, pr);
  }

  peers[index]._m.pop_front();
  if (ec)
  {
    close_peer_connection(index);
    return;
  }
  if (!peers[index]._m.empty())
  {
    write(index);
  }
}

void tcp_server::write(int index)
{
  if (index >= peers.size())
    return;
  string mm = peers[index]._m[0];
  if (mm.find("#full_block") == 0 and mm.length() > 10)
  {
    string mz = mm.substr(mm.length() - 14, 13);
    bool pr = true;
    unsigned long sol = safe_stoull(mz, pr);
  }
  if (index < peers.size() && peers[index].session != NULL && peers[index].connected && peers[index]._strand != NULL)
  {
    boost::asio::async_write(peers[index].session->socket(), boost::asio::buffer(peers[index]._m[0]), peers[index]._strand->wrap(boost::bind(&tcp_server::handle_write, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred, index)));
  }
  else
  {
    boost::system::error_code ec;
    handle_write(ec, 0, index);
  }
}

void tcp_server::strand_write(string message, int index)
{
  if (index >= peers.size())
    return;
  peers[index]._m.push_back(message + "!");
  if (peers[index]._m.size() > 1)
    return;
  write(index);
}

void tcp_server::strand_proceed(int index)
{

  if (index >= peers.size())
    return;
  if (peers[index]._m.size() > 0)
    write(index);
}

void tcp_server::write_to_all_peers(string message)
{
  for (int i = 0; i < peers.size(); i++)
  {
    if (peers[i]._strand != NULL)
      peers[i]._strand->post(boost::bind(&tcp_server::strand_write, this, message, i));
  }
}

void tcp_server::run_network()
{
  unsigned long time_of_now = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
  // connecting to peers
  if (time_of_now - last_peer_connect > CONNECT_TO_PEERS_MILLISECONDS)
  {
    last_peer_connect = time_of_now;
    for (int i = 0; i < peers.size(); i++)
    {
      if (!peers[i].connected)
      {
        try
        {
          peers[i].session = tcp_connection::create(GET_IO_SERVICE(acceptor_));
        }
        catch (...)
        {
          cout << "[*]Creating session threw... nothing major..." << endl;
          continue;
        }
        peers[i].session->id = rng();
        if (peers[i]._strand == NULL)
        {
          try
          {
            peers[i]._strand = new boost::asio::io_service::strand(GET_IO_SERVICE(acceptor_));
          }
          catch (...)
          {
            cout << "[*]Creating strand threw... nothing major..." << endl;
            continue;
          }
        }

        tcp::endpoint *ep;
        try
        {
          ep = new tcp::endpoint(boost::asio::ip::address_v4::from_string(peers[i].ip), peers[i].port);
        }
        catch (...)
        {
          cout << "[*]Creating endpoing to " << peers[i].ip << ":" << peers[i].port << " threw... nothing major..." << endl;
          continue;
        }

        peers[i].session->socket().async_connect(*ep, [this, i](boost::system::error_code const &ec)
                                                 {
                                                   if (!ec)
                                                   {
                                                     if (i < peers.size())
                                                     {
                                                       peers[i].connected = true;
                                                       if (PRINT_PEER_CONNECTION_MESSAGES)
                                                       {
                                                         printf("\033[32;1m[+] Connected to peer %s:%d\033[0m", (peers[i].ip).c_str(), peers[i].port);
                                                         printf("\n");
                                                         fflush(stdout);
                                                       }
                                                       peers[i]._strand->post(boost::bind(&tcp_server::strand_proceed, this, i));
                                                     }
                                                   }
                                                   else
                                                   {
                                                     close_peer_connection(i);
                                                   } });
      }
    }
  }

  // Pings
  if (no_pings < PING_REPEAT && next_ping < time_of_now)
  {

    no_pings++;

    string tt = my_ip + ":" + to_string(my_port) + ":" + to_string(no_pings);
    int mode = no_pings % 2;
    add_ping(tt, 0, mode);

    string s = create__ping(tt, 0, time_of_now, mode);
    ser->write_to_all_peers(s);

    next_ping = time_of_now + 1000 * (PING_MIN_WAIT + (rng() % (PING_MAX_WAIT - PING_MIN_WAIT)));
  }

  // TODO Repeat ? TODO
  auto runcb = [this](boost::system::error_code const &error)
  { run_network(); };
  t->expires_from_now(boost::posix_time::milliseconds(RUN_NETWORK_EACH_MILLISECONDS));
  t->async_wait(runcb);
}

void tcp_server::start_accept()
{
  tcp_connection::pointer new_connection = tcp_connection::create(GET_IO_SERVICE(acceptor_));
  new_connection->id = rng();
  acceptor_.async_accept(new_connection->socket(),
                         boost::bind(&tcp_server::handle_accept, this, new_connection,
                                     boost::asio::placeholders::error));
}

void tcp_server::handle_accept(tcp_connection::pointer new_connection, const boost::system::error_code &error)
{
  if (!error)
  {
    string connecting_ip = new_connection->socket().remote_endpoint().address().to_string();

    if (REJECT_CONNECTIONS_FROM_UNKNOWNS && peer_ips.find(connecting_ip) == peer_ips.end())
    {
      printf("\033[31;1m[-] IP (%s) of peer not in the list of allowed\n\033[0m", connecting_ip.c_str());
    }
    else
    {
      new_connection->start();
      printf("\033[32;1m[+] Connection established from %s:%d\n\033[0m", new_connection->socket().remote_endpoint().address().to_string().c_str(), new_connection->socket().remote_endpoint().port());
    }
  }
  start_accept();
}

void tcp_server::send_remote_attestation_to_peer(uint32_t index)
{
  string attestation_msg = create_remote_attestation_evidence(se_enclave);
  if (attestation_msg.compare("-1") != 0)
  {
    for (size_t i = 0; i < peers.size(); i++)
    {
      if (peers[i].connected && index == i)
      {

        attestation_msg = "#RA_Request," + my_ip + "," + to_string(my_port) + "," + attestation_msg + ",";
        peers[i]._strand->post(boost::bind(&tcp_server::strand_write, this, attestation_msg, index));
        break;
      }
    }
  }
}

void tcp_server::reply_remote_attestation_to_peer(uint32_t index)
{
  string attestation_msg = create_remote_attestation_evidence(se_enclave);
  if (attestation_msg.compare("-1") != 0)
  {
    attestation_msg = "#RA_Reply," + my_ip + "," + to_string(my_port) + "," + attestation_msg + ",";
    peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, attestation_msg, index));
  }
}

void tcp_server::setup_secure_channel_to_peer(uint32_t index)
{

  string ase_msg = create_encrypted_aes_pk(se_enclave, peers[index].uuid);
  if (ase_msg.compare("-1") != 0)
  {
    ase_msg = "#AES_Setup," + my_ip + "," + to_string(my_port) + "," + ase_msg + ",";
    peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, ase_msg, index));
  }
}

void tcp_server::reply_secure_channel_to_peer(uint32_t index)
{
  string aes_reply_msg = "#AES_Reply," + my_ip + "," + to_string(my_port) + ",";
  peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, aes_reply_msg, index));
}

void tcp_server::request_ecdsa_pk_from_peer(uint32_t index)
{
  string request_msg = "#ECDSA_Setup," + my_ip + "," + to_string(my_port) + ",";
  peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, request_msg, index));
}

void tcp_server::reply_ecdsa_pk_to_peer(uint32_t index)
{
  string ecdsa_msg = create_encrypted_ecdsa_pk(se_enclave, peers[index].uuid);
  if (ecdsa_msg.compare("-1") != 0)
  {
    ecdsa_msg = "#ECDSA_Reply," + my_ip + "," + to_string(my_port) + "," + ecdsa_msg + ",";
    peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, ecdsa_msg, index));
  }
}

// When system inits, setup PKI for all nodes
void tcp_server::broadcast_ecdsa_pki_to_peers(uint32_t index)
{
  string pki_msg = create_ecdsa_pki_certificate(se_enclave, peers[index].uuid);
  if (pki_msg.compare("-1") != 0)
  {
    pki_msg = "#PKI_Cert," + my_ip + "," + to_string(my_port) + "," + pki_msg + ",";
    peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, pki_msg, index));
  }
}

void tcp_server::reply_ecdsa_pki_to_peer(uint32_t index)
{
  string pki_reply = "#PKI_Reply," + my_ip + "," + to_string(my_port) + ",";
  peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, pki_reply, index));
}

// local attestation
void tcp_server::send_local_evidence_to_client(vector<std::string> sp, uint32_t index)
{
  string attes_msg = create_local_attestation_evidence(se_enclave, sp);
  if (attes_msg.compare("-1") != 0)
  {
    attes_msg = "#Client_LA_Reply," + my_ip + "," + to_string(my_port) + "," + attes_msg + ",";
    peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, attes_msg, index));
  }
}

void tcp_server::reply_client_channel_setup(uint32_t index)
{
  string return_message = "#Client_AES_Reply," + my_ip + "," + to_string(my_port) + ",";
  peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, return_message, index));
}

void tcp_server::reply_client_messages(uint32_t index, string message)
{
  string msg = "#Client_Reply," + my_ip + "," + to_string(my_port) + "," + message + ",";
  ser->peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, msg, index));
}

// INFO ROTE
int64_t tcp_server::print_time()
{

  std::chrono::microseconds ms = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch());
  return ms.count();
}

// INFO ROTE
void tcp_server::fetch_signed_messages(uint32_t index, string message)
{
  if (message.compare("-1") == 0)
  {
    cout << "[-]Message check error" << endl;
    return;
  }
  if (ser->peers[index].attestState != 0)
  {
    string msg = "#AE_Update_signed," + my_ip + "," + to_string(my_port) + "," + message + ",";
    ser->peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, msg, index));
  }
}
// INFO ROTE
void tcp_server::fetch_echo_messages(uint32_t index, string message)
{
  if (message.compare("-1") == 0)
  {
    cout << "[-]fetch_echo_messages! Message check error" << endl;
    return;
  }
  string msg = "#AE_Update_echo," + my_ip + "," + to_string(my_port) + "," + message + ",";
  peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, msg, index));
}
// INFO ROTE
void tcp_server::fetch_return_echo_messages(uint32_t index, string message)
{
  if (message.compare("-1") == 0)
  {
    cout << "[-]fetch_echo_messages! Message check error" << endl;
    return;
  }
  string msg = "#AE_Update_return_echo," + my_ip + "," + to_string(my_port) + "," + message + ",";
  cout << "debug6 " << index << endl;
  // BUG Usually segmentation fault
  peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, msg, index));
}
// INFO ROTE
void tcp_server::fetch_final_messages(uint32_t index, string message)
{
  if (message.compare("-1") == 0)
  {
    cout << "[-]fetch_echo_messages! Message check error" << endl;
    return;
  }
  string msg = "#AE_Update_final," + my_ip + "," + to_string(my_port) + "," + message + ",";
  peers[index]._strand->post(boost::bind(&tcp_server::strand_write, this, msg, index));
}

// INFO ROTE
void tcp_server::fetch_AE_return_messages(uint32_t index, string message, string message_index)
{
  if (message.compare("-1") == 0)
  {
    cout << "[-]fetch_echo_messages! Message check error" << endl;
    return;
  }
  string msg = "#AE_Return_Final," + my_ip + "," + to_string(my_port) + "," + message + "," + message_index + ",";
  for (size_t i = 0; i < peers.size(); i++)
  {
    if (peers[i].connected && peers[i].uuid == index)
    {
      peers[i]._strand->post(boost::bind(&tcp_server::strand_write, this, msg, i));
      cout << "[+]Re Post thie requests  Now time is " << ser->print_time() << " the message is  " << msg << endl;
      break;
    }
  }
}

void tcp_server::log_file(string message, int64_t timestamp1, int64_t timestamp2, int index)
{
  fstream file;
  file.open("alllog6", ios::out | ios::app);
  if (!file.is_open())
  {
    cout << "[Log]File open failed!" << endl;
    file.close();
  }
  file << message << " start time : " << timestamp1 << " Time : " << timestamp2 - timestamp1 << endl;
  file.close();
}

bool tcp_server::isPKISetup()
{
  int counter_re = 0;
  for (int i = 0; i < peers.size(); i++)
  {
    if (((peers[i].role).compare("se_slave") == 0) && ((peers[i].attestState == SYSTEM_INIT_PKI_SETUP)))
    {
      counter_re++;
    }
    // else
    // {
    //   cout << "Now peer " << i << " state " << peers[i].attestState << endl;
    // }
    if (counter_re == Re_Peers.size())
    {
      for (int j = 0; j < peers.size(); j++)
      {
        if(((peers[j].role).compare("se_slave") == 0)){
          ser->broadcast_ecdsa_pki_to_peers(j);
          ser->set_peer_wait_count(j);
        }
      }
      if (PRINT_ATTESTATION_MESSAGES)
      {
        std::cout << "Master Peer is sync pki" << std::endl;
      }
      return true;
    }
    // else
    // {
    //   std::cout << "Peer is no setup pki " << counter_re << endl;
    // }
  }
  return false;
}

uint32_t tcp_server::get_my_port()
{
  return my_port;
}

void tcp_server::add_bytes_received(uint32_t br, uint32_t mbr)
{
  bytes_received += br;
  bytes_txs_received += mbr;
}

bool tcp_server::add_ping(string tt, int dnext, bool overwrite)
{

  if (overwrite)
  {
    auto it = pings.find(tt);

    if (it == pings.end() || it->second > dnext)
    {
      pings[tt] = dnext;
      return true;
    }
    return false;
  }

  if (pings.find(tt) != pings.end())
    return false;

  pings.insert(make_pair(tt, dnext));
  return true;
}

bool tcp_server::is_peer_connected(uint32_t index)
{
  if (peers[index]._strand != NULL)
  {
    return true;
  }
  else
  {
    return false;
  }
}

uint32_t tcp_server::get_peer_port(uint32_t index)
{
  return peers[index].port;
}

string tcp_server::get_peer_ip(uint32_t index)
{
  return peers[index].ip;
}

uint32_t tcp_server::find_peer_index_by_ip_and_port(string ip, uint32_t port)
{
  for (uint32_t i = 0; i < peers.size(); i++)
  {
    if ((ip.compare(peers[i].ip) == 0) && (port == peers[i].port))
    {
      return i;
    }
  }
  if (PRINT_WARNNING_MESSAGES)
  {
    cout << "[Function] find_peer_index_by_ip_and_port. Peer (" << my_ip << ":" << my_port << ") cannot find peer (" << ip << ":" << port << " )" << endl;
  }
  return -1;
}

uint32_t tcp_server::find_uuid_by_ip_and_port(string ip, uint32_t port)
{
  for (uint32_t i = 0; i < peers.size(); i++)
  {
    if ((ip.compare(peers[i].ip) == 0) && (port == peers[i].port))
    {
      return peers[i].uuid;
    }
  }

  return -1;
}

int tcp_server::get_peers_size()
{
  return peers.size();
}

uint8_t tcp_server::get_peer_attest_state(uint32_t index)
{
  return peers[index].attestState;
}

void tcp_server::set_peer_attest_state(uint32_t index, uint8_t state)
{
  peers[index].attestState = state;
}

uint32_t tcp_server::get_peer_wait_count(uint32_t index)
{
  return peers[index].waiting_count;
}

// set the waiting for on-going remote attestation 3 times
void tcp_server::set_peer_wait_count(uint32_t index)
{
  peers[index].waiting_count = 5;
}

size_t tcp_server::get_peer_uuid(uint32_t index)
{
  return peers[index].uuid;
}

void tcp_server::clear_peer_wait_count(uint32_t index)
{
  peers[index].waiting_count = 0;
}

// decrease the waiting count for on-going remote attestation
void tcp_server::decrease_peer_wait_count(uint32_t index)
{
  peers[index].waiting_count--;
}

void tcp_server::set_uuid(size_t id)
{
  uuid = id;
}

size_t tcp_server::get_uuid()
{
  return uuid;
}

string tcp_server::get_peer_role(size_t index)
{
  return peers[index].role;
}
