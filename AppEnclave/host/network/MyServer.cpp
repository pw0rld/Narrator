
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
#include "MyServer.hpp"
#include "host/system_init.h"
#include "messages.h"
#include "process_buffer.h"

using boost::asio::ip::tcp;
using namespace std;

extern oe_enclave_t *cl_enclave;
extern tcp_server *ser;
extern mt19937 rng;

// extern string my_ip;
bool established_token = false;
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
                                //写入本地文件
                                if (WRITE_SESSIONS_TO_HDD)
                                {
                                  string filename = folder_sessions + "/" + to_string(id);
                                  ofstream file;
                                  file.open(filename, std::ios_base::app);
                                  for (int k = 0; k < length; k++)
                                    file << data_buffer[k];
                                  file << endl;
                                  file.close();
                                }
                                for (int z = 0; z < length; z++)
                                  full_buffer.push_back(data_buffer[z]);
                                ser->add_bytes_received(length, 0);
                                fflush(stdout);
                                process_buffer(full_buffer, ser, cl_enclave);
                                start();
                              }
                            });
  }
  catch (...)
  {
    cout << "async_read_some failed" << endl;
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
    // Make the hash table of peers (used later to avoid connecting such peers as blind peers)
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
    unsigned long nol = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
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
    unsigned long nol = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
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
      if (!peers[i].connected /* || peers[i].session == NULL */)
      {
        try
        {
          peers[i].session = tcp_connection::create(GET_IO_SERVICE(acceptor_));
        }
        catch (...)
        {
          cout << "Creating session threw... nothing major..." << endl;
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
            cout << "Creating strand threw... nothing major..." << endl;
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
          cout << "Creating endpoing to " << peers[i].ip << ":" << peers[i].port << " threw... nothing major..." << endl;
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

  // Repeat
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

int64_t tcp_server::print_time()
{

  std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch());
  // std::cout << ms.count() << std::endl;
  // const boost::posix_time::ptime now = boost::posix_time::microsec_clock::local_time();
  // const boost::posix_time::time_duration td = now.time_of_day();
  // const long hours  = td.hours();
  // const long minutes  = td.minutes();
  // const long seconds  = td.seconds();
  // const long milliseconds = td.total_milliseconds() - (hours * 3600 + minutes * 60 + seconds) * 1000;
  return ms.count();
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
      established_token = true;
      printf("\033[32;1m[+] Connection established from %s:%d\n\033[0m",
             new_connection->socket().remote_endpoint().address().to_string().c_str(), new_connection->socket().remote_endpoint().port());
    }
  }
  start_accept();
}

// Send local attestation challenge to SE
void tcp_server::send_attestation_challenge()
{
  string msg = create_attestation_local_format_setting(cl_enclave);
  if (msg.compare("-1") != 0)
  {
    msg = "#Local_Challenge," + my_ip + "," + to_string(my_port) + "," + msg + ",";
    peers[0]._strand->post(boost::bind(&tcp_server::strand_write, this, msg, 0));
  }
}

// send encrypted aes key to SE
void tcp_server::setup_secure_channel_to_server()
{
  string msg = create_aes_channel(cl_enclave);
  if (msg.compare("-1") != 0)
  {
    msg = "#Client_Channel_Setup," + my_ip + "," + to_string(my_port) + "," + msg + ",";
    peers[0]._strand->post(boost::bind(&tcp_server::strand_write, this, msg, 0));
  }
}

// init the state at SE if not setup previously
void tcp_server::send_client_requests(size_t message_type)
{
  // cout << "Start to send_client_requests.And milliseconds time is " << ser->print_time() << endl;
  string msg = create_client_message(cl_enclave, message_type);
  // cout << "End to send_client_requests.And milliseconds time is " << ser->print_time() << endl;

  if (msg.compare("-1") != 0)
  {
    ser->index_message++;
    msg = "#AE_Update_Counter_Requests," + my_ip + "," + to_string(my_port) + "," + msg + "," + to_string(ser->print_time()) + "," + to_string(ser->index_message);
    peers[0]._strand->post(boost::bind(&tcp_server::strand_write, this, msg, 0));
    // cout << "Create Send client requests over. And milliseconds time is " << ser->print_time() << endl;
  }
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

bool tcp_server::is_server_connected()
{
  if (peers[0]._strand != NULL)
  {
    return true;
  }
  else
  {
    return false;
  }
}

uint32_t tcp_server::get_server_port()
{
  return peers[0].port;
}

string tcp_server::get_server_ip()
{
  return peers[0].ip;
}

bool tcp_server::check_ip_and_port(string ip, uint32_t port)
{
  if ((ip.compare(peers[0].ip) == 0) && (port == peers[0].port))
    return true;
  else
    return false;
}

int tcp_server::get_peers_size()
{
  return peers.size();
}
