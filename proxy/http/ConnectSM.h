/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#pragma once

#include "tscore/ink_platform.h"
#include "P_EventSystem.h"

class HttpSM; // So we can reach through to access the HttpTranact::state
class ConnectSM;
typedef int (ConnectSM::*ConnectSMHandler)(int event, void *data);
typedef void (*ReturnFunc)();

class ConnectSM : public Continuation
{
public:

  enum Action {
    Undefined,
    DnsRequest,
    StartConnect,
    RetryConnect,
    Done
  };

  void start_machine(HttpSM *root_sm, Action next_action);

private:
  ConnectSM::Action _action = Undefined;
  ConnectSM::Action _next_action = Undefined;
  int _max_connect_retries = 0;
  HttpSM *_root_sm = nullptr;
  Action *pending_action        = nullptr;
  ReturnFunc _return_point = nullptr;

  // Event handler methods
  int state_server_open(int event, void *data);
  int state_hostdb_lookup(int event, void *data);

  // Return methods
  void OSDNSLookup();

  // Do the actions needed to move from _state to _next_state
  void transition_state();
  // Call return and move to the next state
  void call_transact_and_transition(ReturnFunc f);


};
