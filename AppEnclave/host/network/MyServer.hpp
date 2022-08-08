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
#include <deque>
#include <set>
#include <random>
#include "../system_init.h"

#if BOOST_VERSION >= 107000
#define GET_IO_SERVICE(s) ((boost::asio::io_context &)(s).get_executor().context())
#else
#define GET_IO_SERVICE(s) ((s).get_io_service())
#endif

using boost::asio::ip::tcp;
using namespace std;

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
  bool connected;
  boost::shared_ptr<tcp_connection> session;
  string pemkey;
  uint32_t waiting_count;
  deque<string> _m;
  boost::asio::io_service::strand *_strand;
} Peer;

typedef tcp::socket *bpv;

class tcp_server
{
public:
  // network funtions
  bool isRequestPending = false;
  tcp_server(boost::asio::io_service &io_service, string ip, uint32_t port);
  void add_peer(Peer p, bool is_connected);
  void add_indirect_peer_if_doesnt_exist(string p);
  void add_peers_ip(string ip);
  int no_peers();
  int no_connected_peers();
  void close_peer_connection(uint32_t no);
  int get_peers_size();
  void run_network();
  void add_bytes_received(uint32_t br, uint32_t mbr);
  bool add_ping(string tt, int dnext, bool overwrite);
  void write_to_all_peers(string message);
  // used funtion
  uint32_t get_server_port();
  string get_server_ip();
  void setup_secure_channel_to_server();
  void send_client_requests(size_t message_type);
  uint32_t get_my_port();
  void send_attestation_challenge();
  bool check_ip_and_port(string ip, uint32_t port);
  bool is_server_connected();
  void reply_aes_secure_channel_to_peer(uint32_t index);
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