
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

#include "get_ip.h"

string get_my_local_ip()
{
    const char *google_dns_server = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    // Socket could not be created
    if (sock < 0)
    {
        cout << "Socket error" << std::endl;
        exit(3);
    }

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(google_dns_server);
    serv.sin_port = htons(dns_port);

    int err = connect(sock, (const struct sockaddr *)&serv, sizeof(serv));
    if (err < 0)
    {
        cout << "Error number: " << errno << ". Error message: " << strerror(errno) << std::endl;
        exit(5);
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr *)&name, &namelen);

    char buffer[80];
    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 80);
    if (p != NULL)
    {
        cout << "[+] Local IP address is: " << buffer << std::endl;
    }
    else
    {
        cout << "Error number: " << errno << ". Error message: " << strerror(errno) << std::endl;
        exit(5);
    }

    close(sock);
    return string(buffer);
}