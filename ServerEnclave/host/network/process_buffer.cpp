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

void process_buffer(string &m, tcp_server *ser, oe_enclave_t *se_enclaves)
{
  size_t pos_h = m.find("#");
  if (pos_h != 0 || pos_h == string::npos)
  {
    if (PRINT_TRANSMISSION_ERRORS)
    {
      cout << "[-] process_buffer error message.something is wrong with the provided message pos: " << pos_h;
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
    else if (sp[0] == "#test_msg")
    {
      string sender_ip;
      uint32_t sender_port;
      string msg;
      // self-added code to debug
      if (PRINT_RECEIVING_MESSAGES)
      {
        printf("\033[32;1m Receive msh \n\033[0m");
        fflush(stdout);
      }
      parse__process_msg(sp, passed, sender_ip, sender_port, msg);
      if (PRINT_RECEIVING_MESSAGES)
      {
        printf("\033[32;1m%s:%d Receive %s \n\033[0m", sender_ip.c_str(), sender_port, msg.c_str());
        fflush(stdout);
      }

      if (CAN_INTERRUPT)
      {
        mythread->interrupt();
      }
    }
    // receiving remote evidence request
    else if (sp[0] == "#RA_Request")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      if (index == -1)
      {
        printf("\033[32;1m Warnning: unknown ra_request message.\n\033[0m");
        fflush(stdout);
        return;
      }
      if (process_attestation_remote_pk_evidence(sp, se_enclaves))
      {
        ser->reply_remote_attestation_to_peer(index); // receiver sends the remote-attestation reply to sender
        if (PRINT_ATTESTATION_MESSAGES)
        {
          cout << "[+]RA_Request process.Peer (" << my_ip << ":" << to_string(my_port) << ") send back remote-attestation to peer (" << sender_ip << ":" << to_string(sender_port) << ")." << std::endl;
        }
      }
    }
    // receiving remote-attestation reply
    else if (sp[0] == "#RA_Reply")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      // receive remote-attestation reply from peers

      if (index == -1)
      {
        printf("\033[32;1m Warnning: unknown ra_reply message.\n\033[0m");
        fflush(stdout);
        return;
      }
      // processing the received remote-attestation reply
      if (ser->get_peer_attest_state(index) == SYSTEM_INIT_START) // make sure initialize the only
      {
        if (process_attestation_remote_pk_evidence(sp, se_enclaves))
        {
          ser->set_peer_attest_state(index, SYSTEM_INIT_SECURE_CHANNEL);
          ser->clear_peer_wait_count(index);
          if (PRINT_ATTESTATION_MESSAGES)
          {
            cout << "[+]RA_Reply process.Peer (" << my_ip << ":" << to_string(my_port) << ") succeed mutual remote attestation with Peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
          }
        }
      }
      else
      {
        if (PRINT_ATTESTATION_MESSAGES)
        {
          cout << "[+]Is is already.Peer (" << my_ip << ":" << to_string(my_port) << ") receive remote-attestation from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        }
      }
    }
    // receiving aes request messages
    else if (sp[0] == "#AES_Setup")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      // sending remote attestation reply to

      if (index == -1)
      {
        printf("\033[32;1m Warnning: unknown aes setup message.\n\033[0m");
        fflush(stdout);
      }
      if (PRINT_ATTESTATION_MESSAGES)
      {
        cout << "[+]AES_Setup process.Peer (" << my_ip << ":" << to_string(my_port) << ") receive aes-setup request from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
      }
      // processing the received remote attestation evidence
      if (process_aes_setup_request(sp, se_enclaves))
      {
        ser->reply_secure_channel_to_peer(index);
        if (PRINT_ATTESTATION_MESSAGES)
        {
          cout << "[+]AES_Setup process.Peer (" << my_ip << ":" << to_string(my_port) << ") send aes-setup reply to peer (" << sender_ip << ":" << to_string(sender_port) << ")." << std::endl;
        }
      }
    }
    // receiving aes reply
    else if (sp[0] == "#AES_Reply")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);

      if (index == -1)
      {
        printf("\033[32;1m Warnning: unknown aes reply message.\n\033[0m");
        fflush(stdout);
      }
      ser->set_peer_attest_state(index, SYSTEM_INIT_EXCHANGE_PK); // set peer state
      ser->clear_peer_wait_count(index);
      if (PRINT_ATTESTATION_MESSAGES)
      {
        cout << "[+]AES_Reply process.Peer (" << my_ip << ":" << to_string(my_port) << ") succeed aes-setup (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
      }
    }
    // receiving ecdsa pk
    else if (sp[0] == "#ECDSA_Setup")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      // sending remote attestation reply to

      if (index == -1)
      {
        printf("\033[32;1m Warnning: unknown ecdsa setup message.\n\033[0m");
        fflush(stdout);
      }
      ser->reply_ecdsa_pk_to_peer(index);
      if (PRINT_ATTESTATION_MESSAGES)
      {
        cout << "[+]ECDSA_Setup process.Peer (" << my_ip << ":" << to_string(my_port) << ") send ecdsa-key to peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
      }
    }
    // receiving aes reply and process
    else if (sp[0] == "#ECDSA_Reply")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      if (index == -1)
      {
        printf("\033[32;1m Warnning: unknown ecdsa reply message.\n\033[0m");
        fflush(stdout);
      }
      // processing the received remote attestation evidence
      //  int uuid = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);
      if (process_edcsa_reply(sp, se_enclaves, index))
      {
        ser->set_peer_attest_state(index, SYSTEM_INIT_PKI_SETUP); // If successful set its status to SYSTEM_INIT_SECURE_CHANNEL
        ser->clear_peer_wait_count(index);

        if (SYSTEM_INIT_EXCHANGE_PK)
        {
          cout << "[+ SYSTEM_INIT_PKI_SETUP +]ECDSA_Reply process.Peer (" << my_ip << ":" << to_string(my_port) << ") receive ecdsa-key from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        }
      }
    }
    // receiving unpack aes decrypt
    else if (sp[0] == "#PKI_Cert")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      if (index == -1)
      {
        printf("\033[32;1m Warnning: unknown ecdsa reply message.\n\033[0m");
        fflush(stdout);
      }
      if (PRINT_ATTESTATION_MESSAGES)
      {
        cout << "[+]PKI_Cert process.Peer (" << my_ip << ":" << to_string(my_port) << ") receive pki-certificate from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
      }
      // processing the received remote attestation evidence
      if (process_ecdsa_pki_certificate(sp, se_enclaves))
      {
        ser->reply_ecdsa_pki_to_peer(index); // This step is reply pki of ecdsa
        // Next peer se will send its record into tendermint
        if (ser->self_tendermint_flag)
        {
          std::cout << "Next peer se will send its record into tendermint" << std::endl;
          string tendermint_data = read_other_info(se_enclaves);
          int is_tru = read_and_verify_tendermint(tendermint_data, se_enclaves);
          if (is_tru == 0)
          {
            // ser->set_peer_attest_state(index, SYSTEM_INIT_DONE);
            cout << "[+]Check tendermint record is not exist " << endl;
            bool is_write = write_tendermint(se_enclaves);
            if (is_write)
            {
              cout << "[+]Record  is successful" << endl;
            }
          }
          else
          {
            cout << "Recorde message into chain failed! " << endl;
            exit(1);
          }
        }
        if (SYSTEM_INIT_EXCHANGE_PK)
        {
          cout << "[+]PKI_Cert process.Peer (" << my_ip << ":" << to_string(my_port) << ") send PKI-reply to peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        }
      }
    }
    // receiving aes reply
    else if (sp[0] == "#PKI_Reply")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      if (index == -1)
      {
        printf("\033[32;1m Warnning: unknown aes reply message.\n\033[0m");
        fflush(stdout);
      }
      // ser->set_peer_attest_state(index, SYSTEM_INIT_UPDATE_CHAIN);
      ser->clear_peer_wait_count(index);
      ser->set_peer_attest_state(index, SYSTEM_INIT_DONE);
      if (PRINT_ATTESTATION_MESSAGES)
      {
        cout << "[+] PKI_Reply process.Peer (" << my_ip << ":" << to_string(my_port) << ") succeed pki-broadcast to peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
      }
    }
    // process local attestation request from AE-client
    else if (sp[0] == "#Local_Challenge")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      ser->send_local_evidence_to_client(sp, index);
      if (PRINT_ATTESTATION_MESSAGES)
      {
        cout << "[+]Local_Challenge process.Peer (" << my_ip << ":" << to_string(my_port) << ") send local-attestation evidence to peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
      }
    }
    else if (sp[0] == "#Client_Channel_Setup")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      if (process_client_channel_setup(sp, se_enclaves))
      {
        ser->reply_client_channel_setup(index);
        if (PRINT_ATTESTATION_MESSAGES)
        {
          cout << "[+]Client_Channel_Setup process.Peer (" << my_ip << ":" << to_string(my_port) << ") send aes-reply to client (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        }
      }
    }
    else if (sp[0] == "#Client_Requests")
    {
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      uint8_t *reply_data;
      size_t reply_data_size;
      size_t reply_type;
      if (process_client_request(sp, se_enclaves, &reply_data, &reply_data_size, &reply_type))
      {
        string message = uint8_to_hex_string(reply_data, reply_data_size);
        if (reply_type == 1)
        {
          ser->reply_client_messages(index, message);
          if (PRINT_ATTESTATION_MESSAGES)
          {
            cout << "[+]Client_Channel_Setup process.Peer (" << my_ip << ":" << to_string(my_port) << ") send request reply to client (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
          }
        }
        else
        {
          printf("\033[32;1m Warnning: unknown message flow%s\n\033[0m", sp[0].c_str());
          fflush(stdout);
        }
      }
    }
    // INFO ROTE; RE accept AE
    // NOTE one step
    else if (sp[0] == "#AE_Update_Counter_Requests")
    {
      // bool pr = true;
      // string sender_ip;
      // uint32_t sender_port;
      // int send_index;
      // string AE_sender_ip = sp[1];
      // uint32_t AE_sender_port = safe_stoi(sp[2], pr);
      // int AE_index = ser->find_peer_index_by_ip_and_port(AE_sender_ip, AE_sender_port);
      if (process_AE_Update_Counter(sp, se_enclaves))
      {
        if (PRINT_ATTESTATION_MESSAGES)
        {
          cout << "[+]Local Re AE_Update_Counter_Requests .Save ae into vector successfule" << endl;
        }
      }
    }
    // INFO ROTE +10
    else if (sp[0] == "#AE_Update_signed") // INFO ROTE; RE accept RE
    {
      int64_t now_time = ser->print_time();
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      string signed_message = process_AE_Update_Echo(sp, se_enclaves);
      ser->fetch_final_messages(index, signed_message); // NOTE tdsc has one step
      cout << "[+]Remote Re processes End the Local Re Echo 1 requests. This requests id is" << sp[5] << " Now time is " << ser->print_time() << " the gap is " << ser->print_time() - now_time << endl;
    }
    // INFO ROTE; RE accept RE +10
    //  frame of OHEI, its message processing of Server is Single instead multithreading
    //  Implement sync of peer must inside enclave.
    //  First host must judge how many peer receiving.If the specified rule is fulfil, then host will request enclave
    //  Second enclave recve host message , it also will check whether the specified rule is fulfil.
    else if (sp[0] == "#AE_Update_echo")
    {
      int64_t now_time = ser->print_time();
      // cout << "[+]Local Re processes Start the Remove Re Echo 1 return requests. This requests id is" << sp[5] << " Now time is " << now_time << endl;
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int batch_group = safe_stoi(sp[5], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      int uuid_index = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);
      if (!(process_AE_Update_Return_Echo_verify(sp, se_enclaves)))
      {
        cout << "【WA】RE main Verify Failed!" << endl;
      }
      // cout << "[+]Local Re processes Start the Remove Re Echo 1 return requests. This requests id is" << sp[5] << " Now time is " << ser->print_time() << " the gap is " << ser->print_time() - now_time << endl;

      ser->Re_tmp_quorum[index] = ""; // activate
      // string signed_message = process_AE_Update_Return_Echo(sp,se_enclaves);
      // ser->Re_tmp_quorum[index] = signed_message;
      // If the specified rule is fulfil,host will request enclave
      // TODO LX condition to f+1
      if (ser->Re_tmp_quorum.size() >= ser->Re_Peers.size() / 2 + 1)
      // if (ser->Re_tmp_quorum.size() == ser->Re_Peers.size()) //NOTE Modified version need test
      {
        ser->now_group_first++;
        now_time = ser->print_time();
        // cout << "[+]Local Re Collected all of the Remove Re Echo 1 return requests. This requests id is" << sp[5] << " Now time is " << now_time << endl;
        string send_message = process_AE_Update_Return_Echo_genc_message(se_enclaves, uuid_index, sp[5]);
        for (map<int, string>::iterator it = ser->Re_tmp_quorum.begin(); it != ser->Re_tmp_quorum.end(); ++it)
        {
          ser->fetch_return_echo_messages(it->first, send_message);
        }
        if (PRINT_ATTESTATION_MESSAGES)
        {
          cout << "[+]Local Re send all of the Echo 1 return requests. This requests id is" << sp[5] << " Now time is " << ser->print_time() << endl;
        }
        ser->Re_tmp_quorum.clear(); // Clear tmp
      }
      else
      {
        cout << "\033[35m Not receiving enough quorum to continue. Next thread will check again \033[0m" << sp[5] << endl;
      }
    }
    // INFO ROTE; RE accept AE+10
    else if (sp[0] == "#AE_Update_return_echo")
    {
      int64_t now_time = ser->print_time();
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      string signed_message = process_AE_Update_Final_Echo(sp, se_enclaves);
      ser->fetch_final_messages(index, signed_message);
      if (PRINT_ATTESTATION_MESSAGES)
      {
        cout << "[+]Remove Re processes Start the Local Re Echo 2 requests. This requests id is" << sp[5] << " Now time is " << ser->print_time() << " the gap is " << ser->print_time() - now_time << endl;
      }
    }
    // INFO ROTE; RE accept AE+10
    else if (sp[0] == "#AE_Update_final")
    {
      int64_t now_time = ser->print_time();
      bool pr = true;
      string sender_ip = sp[1];
      uint32_t sender_port = safe_stoi(sp[2], pr);
      int batch_group = safe_stoi(sp[5], pr);
      int indexb = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);
      if (!(process_AE_Update_Final_verify(sp, se_enclaves)))
      {
        cout << "【WA】RE main Verify Failed!" << endl;
        return;
      }
      ser->m.lock();
      ser->Re_tmp_quorum_finally[indexb] = "1"; // activate
      ser->m.unlock();
      if (ser->Re_tmp_quorum_finally.size() == ser->Re_Peers.size())
      {
        ser->now_group++;
        ser->m.lock();
        ser->Re_tmp_quorum_finally.clear();
        ser->m.unlock();
        bool find_index = true;
        int count_round_4 = 1;
        for (vector<size_t>::iterator it = ser->ae_queues_vector_size.begin(); it != ser->ae_queues_vector_size.end(); it++)
        {
          size_t counter_size = *it;
          if (counter_size == 0 || counter_size > 100)
          {
            cout << "[Worry]Nothing to do " << endl;
            continue;
          }
          ser->m.lock();
          ser->ae_queues_vector_size.erase(it);
          it--;
          ser->m.unlock();
          counter_size = count_round_4 * counter_size;
          int pushcount = ser->ae_queues_vector_process.size();
          json j;
          string tmp_string = "";
          size_t indexkkk = 0;
          int64_t test_time = 0;
          for (int kka = 0; kka < pushcount; kka++)
          {
            if (ser->ae_queues_vector_process.front().timestamp.size())
            {
              if (test_time == 0)
              {
                test_time = stol(ser->ae_queues_vector_process.front().timestamp);
              }
              j[kka] = ser->ae_queues_vector_process.front().timestamp + " @ " + ser->ae_queues_vector_process.front().index_time;
            }
            else
            {
              j[kka] = "";
            }
            indexkkk = ser->ae_queues_vector_process.front().uuid;
            // cout << " k is " << ser->ae_queues_vector_process.front().timestamp << " b is " << ser->ae_queues_vector_process.front().uuid << endl;
            ser->ae_queues_vector_process.pop();
            tmp_string = j.dump();
            ser->fetch_AE_return_messages(indexkkk, "", replace_all(tmp_string, ",", "$"));
          }

          // tmp_string = j.dump();
          // ser->log_file("Vector time is ", ser->print_time(), test_time, indexkkk);
          // for (int kkb = 0; kkb < counter_size; kkb++)
          // {
          // ser->fetch_AE_return_messages(indexkkk, "", replace_all(tmp_string, ",", "$"));
          // }
          cout << "[+]Fetch ae This requests id count is" << pushcount << "Now watting queue size is " << ser->Re_tmp_quorum_finally.size() << " and finish size  " << counter_size << endl;
          break;
        }
      }
      else
      {
        cout << "[+]Local Re Waitting the Remove Re echo 2 return requests. This requests id is" << sp[5] << " Now time is " << now_time << " Now watting queue size is " << ser->Re_tmp_quorum_finally.size() << " and remote peer size is " << ser->Re_Peers.size() << " Now the indexb " << indexb << endl;
      }
    }
    // INFO New
    else if (sp[0] == "#AE_Read_Requests")
    {
      bool pr = true;
      string sender_ip;
      uint32_t sender_port;
      int send_index;
      string AE_sender_ip = sp[1];
      uint32_t AE_sender_port = safe_stoi(sp[2], pr);
      int AE_index = ser->find_peer_index_by_ip_and_port(AE_sender_ip, AE_sender_port);
      if (process_AE_Update_Counter(sp, se_enclaves))
      {
        cout << "[+]Local Re AE_Update_Counter_Requests .Save ae into vector successfule" << endl;
      }
    }

    else
    {
      if (PRINT_WARNNING_MESSAGES)
      {
        printf("\033[32;1m Warnning: unknown message type%s\n\033[0m", sp[0].c_str());
        fflush(stdout);
      }
    }
  }

  if (positions.size() > 1 && positions[p] < m.size())
    m = m.substr(positions[p]);
  else
    m = "";
}
