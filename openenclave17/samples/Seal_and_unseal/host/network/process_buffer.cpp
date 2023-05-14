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

#include "process_buffer.h"
extern mt19937 rng;
extern boost::thread *mythread;
extern unsigned long time_of_start;
extern string my_ip;
extern uint32_t my_port;
extern string my_role;
extern size_t system_state;
extern size_t wait_count;

string &replace_all(string &str, const string &old_value, const string &new_value)
{
  while (true)
  {
    string::size_type pos(0);
    if ((pos = str.find(old_value)) != string::npos)
      str.replace(pos, old_value.length(), new_value);
    else
      break;
  }
  return str;
}

void process_buffer(string &m, tcp_server *ser, oe_enclave_t *attester_enclaves)
{

  size_t pos_h = m.find("#");
  if (pos_h != 0 || pos_h == string::npos)
  {
    if (PRINT_TRANSMISSION_ERRORS)
    {
      cout << "something is wrong with the provided message pos: " << pos_h;
      cout << " m:" << m.size() << ":" << m << ":";
      cout << endl;
      exit(0);
    }
    m = "";
    return;
  }
  map<string, int> passed;
  vector<size_t> positions;
  size_t pos = m.find("#");
  while (pos != string::npos)
  {
    positions.push_back(pos);
    pos = m.find("#", pos + 1);
  }
  positions.push_back(m.size() + 1);
  int p;
  for (p = 0; p < positions.size() - 1; p++)
  {
    string w = m.substr(positions[p], positions[p + 1] - positions[p]);
    if (w[w.size() - 1] != '!')
      break;
    w = w.substr(0, w.size() - 1);
    vector<std::string> sp = split(w, ",");
    if (sp.size() < 1)
      continue;

    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    if (ser->check_ip_and_port(sender_ip, sender_port) == false)
    {
      printf("\033[32;1m Warnning: unknown message type: ip:%s, port:%d.\n\033[0m", sender_ip.c_str(), sender_port);
      fflush(stdout);
      continue;
    }

    if (sp[0] == "#ping")
    {
      string sender_ip;
      uint32_t sender_port;
      string tt;
      uint32_t dnext;
      unsigned long tsec;
      int mode;
      if (!parse__ping(sp, passed, sender_ip, sender_port, tt, dnext, tsec, mode))
      {
        if (p + 2 == positions.size())
          break;
        continue;
      }
      // Add pinger to list of peers
      ser->add_indirect_peer_if_doesnt_exist(sender_ip + ":" + to_string(sender_port));
      // If mode=0, it means we measure latency. Thus once a pingID has been seen, we don't update
      // if mode=1, it means we measure diameter. Thus we update hash pings if dnext is smaller than previously seen
      // If ping seen before, then do nothing
      if (!(ser->add_ping(tt, dnext, mode == 1)))
        continue;
      // Add the file of pings
      unsigned long time_of_now = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
      string filename = string(FOLDER_PINGS) + "/" + my_ip + to_string(my_port);
      ofstream file;
      file.open(filename, std::ios_base::app);
      file << mode << " " << tt << " " << (dnext + 1) << " " << ((time_of_now > tsec) ? (time_of_now - tsec) : 0) << endl;
      file.close();
      // Send ping to other peers
      string s = create__ping(tt, dnext + 1, tsec, mode);
      ser->write_to_all_peers(s);
    }
    // receive local attestation evidence
    else if (sp[0] == "#Client_LA_Reply")
    {

      if (PRINT_ATTESTATION_MESSAGES)
      {
        cout << "Client (" << my_ip << ":" << to_string(my_port) << ") receive local-attestation from SE (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
      }

      if (process_attestation_local_pk_evidence(sp, attester_enclaves))
      {
        system_state = SYSTEM_INIT_SECURE_CHANNEL;
        wait_count = 0;
        if (PRINT_ATTESTATION_MESSAGES)
        {
          cout << "Client (" << my_ip << ":" << to_string(my_port) << ") succeed local-attestation with SE (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        }
      }
    }
    // receiving aes reply
    else if (sp[0] == "#Client_AES_Reply")
    {
      system_state = SYSTEM_LOAD_STATE;
      wait_count = 0;
      if (PRINT_ATTESTATION_MESSAGES)
      {
        cout << "Client (" << my_ip << ":" << to_string(my_port) << ") succeed aes-channel setup with SE (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
      }
    }
    // receiving request reply
    else if (sp[0] == "#Client_Reply")
    {
      size_t is_ready;
      if (process_server_reply(sp, attester_enclaves, &is_ready))
      {
        if (is_ready == 1)
        {
          system_state = SYSTEM_INIT_DONE;
          wait_count = 0;
        }
      }
    }
    else if (sp[0] == "#AE_Return_Final")
    {
      size_t is_ready;
      // Update Requests
      int64_t time_send = 0;
      // if (process_server_reply(sp, attester_enclaves, &is_ready))
      // {
      // cout << "sp[4]" << sp[4] << endl;
      string temp_ = "";
      temp_ = replace_all(sp[4], "$", ",");
      // cout << "temp_ " << temp_ << endl;
      json j = json::parse(temp_);
      string temp_2 = "";
      string tmp_string = "";
      for (json::iterator it = j.begin(); it != j.end(); ++it)
      {
        temp_2 = *it;
        temp_2 = replace_all(temp_2, "\"", "");
        cout << "temp_2 " << temp_2 << endl;
        time_send = 0;
        if (temp_2.size())
          time_send = std::stol(temp_2);
        if (process_read_requests_reply(sp, attester_enclaves, &is_ready))
        {
          tmp_string = " and t1ime is " + to_string(ser->print_time()) + "  orginal time " + to_string(time_send) + " ppp ";
          ser->log_file("Finally.txt", ser->print_time() - time_send, tmp_string);
        }
        // tmp_string = " and t1ime is " + to_string(ser->print_time()) + "  orginal time " + to_string(time_send) + " ppp ";
        // ser->log_file("Finally.txt", ser->print_time() - time_send, tmp_string);
        ser->num_test--;
      }
      tmp_string = "";
      if ((ser->print_time2() - ser->start_times) <= 10 /*&& ser->num_test == 0*/)
      {
        tmp_string += " and t1ime is " + to_string(ser->print_time());
        // ser->log_file("Finally.txt", 1, tmp_string);
        // ser->send_client_requests(STATE_FETCH);
        ser->send_read_requests(STATE_FETCH);
      }
      else if ((ser->print_time2() - ser->start_times) > 10)
      {
        ser->log_file("Finally.txt", 1, "发完了！发完了！发完了！发完了！发完了！发完了！");

        cout << "发完了！" << endl;
      }
      // ser->send_client_requests(STATE_FETCH);
    }
    else if (sp[0] == "#fetch_AE_read_messages")
    {
      size_t is_ready = 0;
      int64_t time_send = 0;
      // if (process_server_reply(sp, attester_enclaves, &is_ready))
      // {
      string temp_ = "";
      temp_ = replace_all(sp[4], "$", ",");
      json j = json::parse(temp_);
      string temp_2 = "";
      string tmp_string = "";
      for (json::iterator it = j.begin(); it != j.end(); ++it)
      {
        temp_2 = *it;
        temp_2 = replace_all(temp_2, "\"", "");
        time_send = std::stol(temp_2);
        if (process_read_requests_reply(sp, attester_enclaves, &is_ready))
        {
          tmp_string = " and t1ime is " + to_string(ser->print_time()) + "  orginal time " + to_string(time_send) + " ppp ";
          ser->log_file("Finally.txt", ser->print_time() - time_send, tmp_string);
        }
        ser->num_test--;
      }

      if ((ser->print_time2() - ser->start_times) <= 10)
      {
        tmp_string += " and t1ime is " + to_string(ser->print_time());
        ser->send_read_requests(STATE_FETCH);
      }
      else
      {
        ser->log_file("Finally.txt", 1, "发完了！发完了！发完了！发完了！发完了！发完了！");
        cout << "发完了！" << endl;
      }
    }
    else
    {
      if (PRINT_WARNNING_MESSAGES)
      {
        printf("\033[32;1m Warnning: unknown message type.\n\033[0m");
        fflush(stdout);
      }
    }
  }

  if (positions.size() > 1 && positions[p] < m.size())
    m = m.substr(positions[p]);
  else
    m = "";
}
