#include "ip_requests.h"
#include "misc.h"
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

extern string my_ip;
extern uint32_t my_port;
//TODO change it to read file
std::string tendermint_url = "http://10.20.61.124:26657";
using namespace boost::archive::iterators;

bool key_present(string key, map<string, int> &passed)
{
  if (passed.find(key) != passed.end())
    return true;
  passed.insert(make_pair(key, 1)); //有啥用？
  return false;
}

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

string create__ping(string tt, uint32_t dnext, unsigned long tsec, int mode)
{
  string s = "#ping," + my_ip + "," + to_string(my_port) + "," + tt + "," + to_string(dnext) + "," + to_string(tsec) + "," + to_string(mode);
  return s;
}

bool parse__ping(vector<std::string> sp, map<string, int> &passed, string &sender_ip, uint32_t &sender_port, string &tt, uint32_t &dnext, unsigned long &tsec, int &mode)
{
  if (sp.size() < 7)
    return false;
  if (key_present(sp[0] + sp[1] + sp[2], passed))
    return false;
  bool pr = true;
  sender_ip = sp[1];
  sender_port = safe_stoi(sp[2], pr);
  tt = sp[3];
  dnext = safe_stoi(sp[4], pr);
  tsec = safe_stoull(sp[5], pr);
  mode = safe_stoi(sp[6], pr);
  if (PRINT_TRANSMISSION_ERRORS && !(pr))
  {
    cout << "Could not get proper values of ping" << endl;
    cout << pr << endl;
    return false;
  }
  return true;
}

bool parse__process_msg(vector<std::string> sp, map<string, int> &passed, string &sender_ip, uint32_t &sender_port, string &msg)
{
  if (sp.size() < 10)
    return false;
  if (key_present(sp[0] + sp[1] + sp[2] + sp[3] + sp[4] + sp[5], passed))
    return false;

  bool pr = true;
  sender_ip = sp[1];
  sender_port = safe_stoi(sp[2], pr);
  msg = sp[3];

  if (PRINT_TRANSMISSION_ERRORS && !(pr && sender_ip.size() > 0))
  {
    cout << "Could not get proper values of process_block" << endl;

    for (int i = 1; i <= 5; i++)
      cout << sp[i] << endl;

    return false;
  }
  return true;
}

inline int boost_http_sync_client(const std::string &server, const std::string &port, const std::string &path,
                                  std::string &out_response_status_line, std::string &out_response_header, std::string &out_response_data)
{
  try
  {
    boost::asio::io_service io_service;

    // Get a list of endpoints corresponding to the server name.
    tcp::resolver resolver(io_service);
    tcp::resolver::query query(server, port /*"http"*/);
    tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

    // Try each endpoint until we successfully establish a connection.
    tcp::socket socket(io_service);
    boost::asio::connect(socket, endpoint_iterator);
    // TODO should add a timeout
    // struct timeval tv;
    // tv.tv_sec = 15;
    // tv.tv_usec = 0;
    // setsockopt(socket SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Form the request. We specify the "Connection: close" header so that the
    // server will close the socket after transmitting the response. This will
    // allow us to treat all data up until the EOF as the content.
    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "GET " << path << " HTTP/1.0\r\n";
    request_stream << "Host: " << server << "\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: close\r\n\r\n";

    cout << "request " << path << endl;

    // Send the request.
    boost::asio::write(socket, request);

    // Read the response status line. The response streambuf will automatically
    // grow to accommodate the entire line. The growth may be limited by passing
    // a maximum size to the streambuf constructor.
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\r\n");

    if (true)
    {
      boost::asio::streambuf::const_buffers_type cbt = response.data();
      std::string temp_data(boost::asio::buffers_begin(cbt), boost::asio::buffers_end(cbt));
      std::size_t idx = temp_data.find('\n');
      idx == std::string::npos ? temp_data.size() : idx;
      out_response_status_line = temp_data.substr(0, idx + 1);
    }

    // Check that response is OK.
    std::istream response_stream(&response);
    std::string http_version;
    response_stream >> http_version;
    unsigned int status_code;
    response_stream >> status_code;
    std::string status_message;
    std::getline(response_stream, status_message);
    if (!response_stream || http_version.substr(0, 5) != "HTTP/")
    {
      std::cout << "Invalid response\n";
      return 1;
    }
    if (status_code != 200)
    {
      std::cout << "Response returned with status code " << status_code << "\n";
      return 1;
    }

    // Read the response headers, which are terminated by a blank line.
    boost::asio::read_until(socket, response, "\r\n\r\n");
    if (true)
    {
      boost::asio::streambuf::const_buffers_type cbt = response.data();
      std::string temp_data(boost::asio::buffers_begin(cbt), boost::asio::buffers_end(cbt));
      std::size_t idx = temp_data.find("\r\n\r\n");
      idx == std::string::npos ? temp_data.length() : idx;
      out_response_header = temp_data.substr(0, idx + 2);
    }

    // Process the response headers.
    std::string header;
    while (std::getline(response_stream, header) && header != "\r")
      ; // std::cout << header << "\n";
    // std::cout << "\n";

    // Write whatever content we already have to output.
    // if (response.size() > 0)
    //    std::cout << &response;
    if (true)
    {
      boost::asio::streambuf::const_buffers_type cbt = response.data();
      out_response_data = std::string(boost::asio::buffers_begin(cbt), boost::asio::buffers_end(cbt));
    }

    // Read until EOF, writing data to output as we go.
    boost::system::error_code error;
    while (boost::asio::read(socket, response, boost::asio::transfer_at_least(1), error))
    {
      boost::asio::streambuf::const_buffers_type cbt = response.data();
      out_response_data = std::string(boost::asio::buffers_begin(cbt), boost::asio::buffers_end(cbt));
    }
    if (error != boost::asio::error::eof)
      throw boost::system::system_error(error);
  }
  catch (std::exception &e)
  {
    std::cout << "Exception: " << e.what() << "\n";
    return -1;
  }

  return 0;
}

inline int parse_url(const std::string &url, std::string &out_server, std::string &out_port, std::string &out_path)
{
  const std::string http___ = "http://";
  const std::string https___ = "https://";
  std::string temp_data = url;

  if (temp_data.find(http___) == 0)
    temp_data = temp_data.substr(http___.length());
  else if (temp_data.find(https___) == 0)
    temp_data = temp_data.substr(https___.length());
  else
    return -1;

  std::size_t idx = temp_data.find('/');
  if (std::string::npos == idx)
  {
    out_path = "/";
    idx = temp_data.size();
  }
  else
  {
    out_path = temp_data.substr(idx);
  }

  out_server = temp_data.substr(0, idx);
  idx = out_server.find(':');
  if (std::string::npos == idx)
  {
    out_port = "http";
    out_port = "80";
  }
  else
  {
    out_port = out_server.substr(idx + 1);
    out_server = out_server.substr(0, idx);
  }

  return 0;
}
//
int get_url_response(const std::string &url, std::string &out_response_data)
{
  int rv = 0;
  do
  {
    std::string server;
    std::string port;
    std::string path;
    rv = parse_url(url, server, port, path);
    if (rv)
      break;
    std::string out_response_status_line;
    std::string out_response_header;
    cout << "path " << path << endl;
    rv = boost_http_sync_client(server, port, path, out_response_status_line, out_response_header, out_response_data);
    if (rv)
      break;
  } while (false);
  return rv;
}
//
int parse_hq_sinajs_cn_and_get_last_price(const std::string &market_data, double &last_price)
{
  std::string temp_data = market_data;
  std::size_t idx;

  idx = temp_data.find('"');
  if (std::string::npos == idx)
    return -1;
  temp_data = temp_data.substr(idx + 1);

  idx = temp_data.find('"');
  if (std::string::npos == idx)
    return -1;
  temp_data = temp_data.substr(0, idx);

  std::vector<std::string> fields;
  std::size_t beg_idx, end_idx;
  for (beg_idx = end_idx = 0; (end_idx = temp_data.find(',', beg_idx)) != std::string::npos; beg_idx = end_idx + 1)
    fields.push_back(temp_data.substr(beg_idx, end_idx - beg_idx));
  fields.push_back(temp_data.substr(beg_idx));

  if (fields.size() != 33)
    return -1;

  last_price = atof(fields[3].c_str());

  return 0;
}

bool Base64Decode(const string &input, string *output)
{
  typedef transform_width<binary_from_base64<string::const_iterator>, 8, 6> Base64DecodeIterator;
  stringstream result;
  try
  {
    copy(Base64DecodeIterator(input.begin()), Base64DecodeIterator(input.end()), ostream_iterator<char>(result));
  }
  catch (...)
  {
    return false;
  }
  *output = result.str();
  return output->empty() == false;
}

string binaryToHex(const string &binaryStr)
{
  string ret;
  static const char *hex = "0123456789ABCDEF";
  for (auto c : binaryStr)
  {
    ret.push_back(hex[(c >> 4) & 0xf]); //取二进制高四位
    ret.push_back(hex[c & 0xf]);        //取二进制低四位
  }
  return ret;
}

/**
 * @brief This function is read something and vrify it.
 * -1 is verify failed ed25519
 *  0 is verify successfull but record is not exist
 *  1 is verify successful and record is exist
 *
 * @param data
 * @param enclave
 * @return true
 * @return false
 */
int read_and_verify_tendermint(std::string data, oe_enclave_t *enclave)
{
  // Ledger.Read()
  int ret = 0;
  oe_result_t result = OE_OK;
  std::string url = tendermint_url + "/abci_query?data=\"" + data + "\"";
  std::string response_data = "";
  ret = get_url_response(url, response_data);
  if (ret)
  {
    cout << "Get information from tendermint error" << endl;
    return -1;
  }

  std::cout << "response_data " << response_data << std::endl;
  json j = json::parse(response_data);
  std::string codespace = j["result"]["response"]["codespace"].dump(); // sync with tendermint return message
  std::string log = j["result"]["response"]["log"].dump();
  std::string height = j["result"]["response"]["height"].dump();
  std::string signture = "";
  std::string value = j["result"]["response"]["value"].dump();
  std::cout << "codespace " << codespace << std::endl;
  log = replace_all(log, "\"", "");
  height = replace_all(height, "\"", "");
  codespace = replace_all(codespace, "\"", "");
  value = replace_all(value, "\"", "");
  string source_text = "";
  source_text = log + height;
  std::cout << "source_text " << source_text << std::endl;
  uint8_t *source_text_uint;
  source_text_uint = (uint8_t *)malloc(source_text.size() + 1);
  memset(source_text_uint, 0, source_text.size() + 1);
  memcpy(source_text_uint, source_text.c_str(), source_text.size());
  Base64Decode(codespace, &signture);
  uint8_t *signture_text_uint;
  signture_text_uint = (uint8_t *)malloc(signture.size() + 1);

  memset(signture_text_uint, 0, 64);
  memcpy(signture_text_uint, signture.c_str(), 64);
  size_t source_text_len = source_text.size();
  size_t signture__len = 64;

  result = verify_ed25519(
      enclave,
      &ret,
      signture_text_uint,
      signture__len,
      source_text_uint,
      source_text_len);
  if ((result != OE_OK) || (ret != 0))
  {
    cout << "Failed to verify ed25519 " << endl;
    return -1;
  }
  free(source_text_uint);
  source_text_uint = NULL;
  free(signture_text_uint);
  signture_text_uint = NULL;
  if (log.compare("exists") == 0)
  { // If the tendermint exist the record, return failed
    cout << "[-The record is exist-]" << endl;
    return 1;
  }
  else // does not exist
  {
    cout << "[-The record is not exist-]" << endl;
    return 0;
  }
}

std::string to_hex(uint8_t *data, size_t data_size)
{
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < data_size; i++)
  {
    oss << std::setw(2) << (unsigned int)data[i];
  }
  return oss.str();
}

std::string uint8_to_hex_stringb(const uint8_t *v, const size_t size)
{
  std::stringstream output;
  output << std::hex << std::setfill('0');
  for (int i = 0; i < size; i++)
  {
    output << std::hex << std::setw(2) << static_cast<int>(v[i]);
  }
  return output.str();
}

/**
 * @brief This function is write something into tendermint
 *
 * @param enclave
 * @return true
 * @return false
 */
bool write_tendermint(oe_enclave_t *enclave)
{
  int ret;
  uint8_t *publickey_id;
  size_t publickey_id_size;
  uint8_t *sgx_uid;
  size_t sgx_uid_size;
  oe_result_t result = OE_OK;
  //TODO LX string sgx_blob = get_cert_info()
  result = LedgerRead_key(
      enclave,
      &ret,
      &publickey_id,
      &publickey_id_size);
      
  string publickey_id_s = uint8_to_hex_stringb(publickey_id, publickey_id_size);
  string sgx_uid_s = uint8_to_hex_stringb(sgx_uid, sgx_uid_size);
  string tendermint_data = publickey_id_s + sgx_uid_s + "22"; // TODO '22' which is sgx_blob should be produces by get_cert_info()
  cout << "tendermint_data " << tendermint_data << endl;

  std::string url = tendermint_url + "/broadcast_tx_commit?tx=\"" + tendermint_data + "\"";
  std::string response_data2 = "";
  ret = get_url_response(url, response_data2);
  free(publickey_id);
  publickey_id = NULL;
  free(sgx_uid);
  sgx_uid = NULL;
  if (ret)
  {
    cout << "Broadcast_tx_commit from tendermint error" << endl;
    return false;
  }
  ret = read_and_verify_tendermint(tendermint_data, enclave);
  if (ret == 1)
  {
    return true;
  }
  else
  {
    return false;
  }
}

string read_other_info(oe_enclave_t *enclave)
{
  int ret;
  uint8_t *sgx_publickey;
  size_t sgx_publickey_size;
  // uint8_t *sgx_uid;
  // size_t sgx_uid_size;
  oe_result_t result = OE_OK;
  result = LedgerRead_key(
      enclave,
      &ret,
      &sgx_publickey,
      &sgx_publickey_size);

  string sgx_publickey_s = uint8_to_hex_stringb(sgx_publickey, sgx_publickey_size);
  // string sgx_uid_s = uint8_to_hex_stringb(sgx_uid, sgx_uid_size);
  string tendermint_data = sgx_publickey_s + "22";
  // TODO 
  // free(sgx_uid);
  // sgx_uid = NULL;
  free(sgx_publickey);
  sgx_publickey = NULL;
  return tendermint_data;
}

bool checkTendermintSetup(size_t uuid, oe_enclave_t *enclave)
{
  int ret;
  uint8_t *publickey_id;
  size_t publickey_id_size;
  uint8_t *sgx_uid;
  size_t sgx_uid_size;
  oe_result_t result = OE_OK;
  result = LedgerRead_other_key(
      enclave,
      &ret,
      &publickey_id,
      &publickey_id_size,
      &sgx_uid,
      &sgx_uid_size, uuid);

  string publickey_id_s = uint8_to_hex_stringb(publickey_id, publickey_id_size);

  string sgx_uid_s = uint8_to_hex_stringb(sgx_uid, sgx_uid_size);
  string tendermint_data = publickey_id_s + sgx_uid_s + "22";
  ret = read_and_verify_tendermint(tendermint_data, enclave);
  free(sgx_uid);
  sgx_uid = NULL;
  free(publickey_id);
  publickey_id = NULL;
  if (ret == 1)
  {
    cout << "check tendermint successful" << endl;
    return true;
  }
  else if (ret == 0)
  {
    cout << "This peer record is not exist in tendermint" << endl;
    return false;
  }
  else
  {
    cout << "Verify failed !!!" << endl;
    exit(1);
  }
}
