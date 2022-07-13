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

#ifndef MYSERVER_HPP
#define MYSERVER_HPP

#include <openenclave/host.h>
#include <openenclave/attestation/sgx/evidence.h>
#include "attestation_u.h"

#include <ctime>
#include <iostream>
#include <string>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <vector>
#include <queue>
#include <deque>
#include <set>
#include <mutex>
#include <random>
#include "../system_init.h"
#include "json.hpp"

#if BOOST_VERSION >= 107000
#define GET_IO_SERVICE(s) ((boost::asio::io_context &)(s).get_executor().context())
#else
#define GET_IO_SERVICE(s) ((s).get_io_service())
#endif

using boost::asio::ip::tcp;
using namespace std;
using json = nlohmann::json;
extern unsigned long time_of_start;

#define max_lengths (32 * 1024 * 1024) // max length of receiving buffer

class tcp_connection : public boost::enable_shared_from_this<tcp_connection>
{
public:
  typedef boost::shared_ptr<tcp_connection> pointer;
  static pointer create(boost::asio::io_service &io_service);
  tcp::socket &socket();
  void start();

  tcp_connection(boost::asio::io_service &io_service);

  uint32_t id;

private:
  tcp::socket socket_;
  std::string message_;
  char data_[max_lengths];
  boost::array<char, max_lengths> data_buffer;
  string full_buffer;
};

typedef struct Peers
{
  string ip;
  uint32_t port;
  string role;
  size_t uuid;
  bool connected;
  uint8_t attestState;
  boost::shared_ptr<tcp_connection> session;
  string pemkey;
  uint32_t waiting_count;
  deque<string> _m;
  boost::asio::io_service::strand *_strand;
} Peer;

typedef struct ae_queue
{
  int index = 0;
  size_t uuid = 0;
  uint8_t encrypt_data[2048] = {0};
  uint8_t encrypt_data_size = 0;
  string index_time = "";
  string timestamp = "";
  bool first_connect = false;
  int round = 0;
} ae_queues;

typedef struct ae_info
{
  int index = 0;
  int64_t return_time = 0;
  int64_t echo_time = 0;
  int64_t return_echo_time = 0;
  int64_t finally_time = 0;
} ae_infos;

typedef struct ae_queueb
{
  int index = 0;
  size_t uuid = 0;
  uint8_t encrypt_data[2048] = {0};
  uint8_t encrypt_data_size = 0;
} ae_queuesb;

typedef struct Re_pipline
{
  int index = 0;
  size_t uuid = 0;
  uint8_t encrypt_data[2048] = {0};
  uint8_t encrypt_data_size = 0;
  int round = 0;
} Re_piplines;

typedef tcp::socket *bpv;

class tcp_server
{
public:
  // network funtions
  int now_group = 0;
  int now_group_first = 0;
  int batch_size = 1;
  std::map<int, string> Re_tmp_quorum;
  std::vector<int> test_vector;
  std::map<int, string> Re_tmp_quorum_finally;
  std::map<int, std::map<string, uint32_t>> Re_Peers;
  std::vector<ae_infos> ae_infos_vector;
  std::vector<ae_queues> ae_queues_vector;
  // std::vector<ae_queues> ae_queues_vector_process;
  std::queue<ae_queues> ae_queues_vector_process;
  std::vector<Re_piplines> Re_piplines_vector;
  std::vector<size_t> ae_queues_vector_size;
  tcp_server(boost::asio::io_service &io_service, string ip, uint32_t port);
  void add_peer(Peer p, bool is_connected);
  void add_indirect_peer_if_doesnt_exist(string p);
  void add_peers_ip(string ip);
  int no_peers();
  int no_connected_peers();
  void print_peers();
  void close_peer_connection(uint32_t no);
  void write_to_all_peers(string message);
  void run_network();
  void add_bytes_received(uint32_t br, uint32_t mbr);
  bool add_ping(string tt, int dnext, bool overwrite);
  // SE peers side funtion
  int get_peers_size();
  uint32_t get_my_port();
  void send_remote_attestation_to_peer(uint32_t index);
  void reply_remote_attestation_to_peer(uint32_t index);
  uint32_t find_peer_index_by_ip_and_port(string ip, uint32_t port);
  uint32_t find_uuid_by_ip_and_port(string ip, uint32_t port);
  bool is_peer_connected(uint32_t index);
  uint32_t get_peer_port(uint32_t index);
  string get_peer_ip(uint32_t index);
  size_t get_peer_uuid(uint32_t index);
  void set_peer_attest_state(uint32_t index, uint8_t state);
  uint8_t get_peer_attest_state(uint32_t index);
  // uint32_t get_peer_port(uint32_t index);
  uint32_t get_peer_wait_count(uint32_t index);
  void set_peer_wait_count(uint32_t index);
  void clear_peer_wait_count(uint32_t index);
  void decrease_peer_wait_count(uint32_t index);
  void setup_secure_channel_to_peer(uint32_t index);
  void reply_secure_channel_to_peer(uint32_t index);
  void request_ecdsa_pk_from_peer(uint32_t index);
  void reply_ecdsa_pk_to_peer(uint32_t index);
  void broadcast_ecdsa_pki_to_peers(uint32_t index);
  void reply_ecdsa_pki_to_peer(uint32_t index);
  bool isPKISetup();
  void set_uuid(size_t id);
  void log_file(string message, int64_t timestamp1, int64_t timestamp2, int index);
  size_t get_uuid();
  string get_peer_role(size_t index);
  // client side functions
  void send_local_evidence_to_client(vector<std::string> sp, uint32_t index);
  void reply_client_channel_setup(uint32_t index);
  void reply_client_messages(uint32_t index, string message);
  void fetch_signed_messages(uint32_t index, string message);
  void fetch_echo_messages(uint32_t index, string message);
  void fetch_return_echo_messages(uint32_t index, string message);
  void fetch_final_messages(uint32_t index, string message);
  void fetch_AE_return_messages(uint32_t index, string message, string message_index);
  int64_t print_time();

private:
  void start_accept();
  void handle_accept(tcp_connection::pointer new_connection, const boost::system::error_code &error);
  void handle_write(boost::system::error_code ec, size_t length, int index);
  void write(int index);
  void strand_write(string message, int index);
  void strand_proceed(int index);

  // ip info
  string my_ip;
  uint32_t my_port;
  size_t uuid;
  tcp::acceptor acceptor_;
  boost::asio::io_service my_io_service;
  // Peers
  std::vector<Peers> peers;
  std::map<string, int> speers;
  std::set<string> peer_ips;
  // Pings
  std::map<string, int> pings;
  unsigned long next_ping;
  unsigned int no_pings;
  std::unique_ptr<boost::asio::deadline_timer> t;
  unsigned long last_peer_connect;
  unsigned long bytes_received;
  unsigned long bytes_txs_received;
};

#endif