
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
#ifndef SYSTEM_INIT_H
#define SYSTEM_INIT_H


#define SYSTEM_INIT_START           0
#define SYSTEM_INIT_SECURE_CHANNEL  1     
#define SYSTEM_INIT_EXCHANGE_PK     2
#define SYSTEM_INIT_PKI_SETUP       3
#define SYSTEM_INIT_UPDATE_CHAIN    4
#define SYSTEM_INIT_DONE            5


/* The system setup process
Master ---------->  remote evidence ----------> slave 
Master <----------  remote evidence <---------- slave
Master ---------->  AES pk and nonce ---------> slave 
Master <----------  AES        reply <--------- slave 
Master ---------->  ECDSA key request --------> slave
Master <----------  ECDSA        key <--------- slave
Master ---------->  Singed PKI certificate ---> slave 
Master <----------  PKI certificate key <------ slave
Slave & Master ---> Init Messgae -------------> blockchain
Slave & Master <--- Reply messgae <------------ blockchain
Slave & Master System Init Done
*/

void system_init( );
#endif
