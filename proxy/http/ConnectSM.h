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
class ProxyTransaction;
class NetVConnection;
class HostDBInfo;
typedef int (ConnectSM::*ConnectSMHandler)(int event, void *data);

struct ConnectAction : public Action {
  ConnectAction() {}
  void cancel(Continuation *c = nullptr) override;
  void
  init(ConnectSM *sm_arg)
  {
    sm = sm_arg;
  };
  ConnectSM *sm = nullptr;
};

class ConnectSM : public Continuation
{
public:
  ConnectSM() { _captive_action.init(this); }

  enum ReturnState {
    UndefinedState,
    DnsHostdbSuccess,
    ServerTxnCreated,
    Tunnel,
    ErrorForbid,
    ErrorResponse,
    ErrorThrottle,
    ErrorTransparent,
    ErrorDNS
  };

  ReturnState _return_state = UndefinedState;

  ProxyTransaction *
  release_server_txn()
  {
    auto retval = _server_txn;
    _server_txn = nullptr;
    return retval;
  }
  NetVConnection *
  get_netvc() const
  {
    return _netvc;
  }

  void cleanup();

  Action *acquire_txn(HttpSM *sm = nullptr, bool raw = false);
  Action *retry_connection(HttpSM *sm = nullptr);

  Action *acquire_dns(HttpSM *sm);
  Action *do_dns_lookup(HttpSM *sm = nullptr);
  Action *do_hostdb_lookup(HttpSM *sm = nullptr);

  void
  cancel_pending_action()
  {
    if (_pending_action) {
      _pending_action->cancel();
    }
  }

  void
  set_server_txn(ProxyTransaction *txn)
  {
    _server_txn = txn;
  }

  HttpSM *
  get_root_sm() const
  {
    return _root_sm;
  }
  void init(HttpSM *sm);

  bool do_retry_request();

private:
  int _max_connect_retries      = 0;
  HttpSM *_root_sm              = nullptr;
  Action *_pending_action       = nullptr;
  ProxyTransaction *_server_txn = nullptr;
  NetVConnection *_netvc        = nullptr;
  ConnectAction _captive_action;

  enum ConnectSMState {
    UndefinedSMState,
    WaitConnect,
    RetryConnect,
    FailConnect,
    WaitAddress,
    RetryAddress,
  } _sm_state = UndefinedSMState;

  bool is_private() const;

  // Event handler methods
  int state_http_server_open(int event, void *data);
  int state_http_server_raw_open(int event, void *data);
  int state_hostdb_lookup(int event, void *data);
  int state_mark_os_down(int event, void *data);
  void process_hostdb_info(HostDBInfo *r);
  void process_srv_info(HostDBInfo *r);
  void delete_server_rr_entry(int max_retries);
  void mark_host_failure(HostDBInfo *info, time_t time_down);
  void do_hostdb_update_if_necessary();
  bool ReDNSRoundRobin();

  /* Because we don't want to take a session from a shared pool if we know that it will be private,
   * but we cannot set it to private until we have an attached server session.
   * So we use this variable to indicate that
   * we should create a new connection and then once we attach the session we'll mark it as private.
   */
  bool will_be_private_ss = false;
};
