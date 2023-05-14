
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

#define MESSAGE_WAIT_COUNT 5

#define SYSTEM_ATTESTATION          0
#define SYSTEM_INIT_SECURE_CHANNEL  1     
#define SYSTEM_LOAD_STATE           2
#define SYSTEM_INIT_STATE           3
#define SYSTEM_GET_STATE            4
#define SYSTEM_INIT_DONE            5


/* The system setup process
Client ------->  local attes challege --------> SE 
Client <-------  local attes evidence <-------- SE
Client ------->  ASE             key  --------> SE 
Client <-------  AES           reply  <-------- SE
Client ------->  Obtain/init State    --------> SE 
Client <-------  Requat        reply  <-------- SE
*/

void system_init( );
#endif
