/** @file

  Http1ClientTransaction.cc - The Client Transaction class for Http1*

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

#include "Http1ClientTransaction.h"
#include "Http1ClientSession.h"
#include "HttpSM.h"

void
Http1ClientTransaction::release()
{
  // Must set this inactivity count here rather than in the session because the state machine
  // is not available then
  MgmtInt ka_in = _sm->t_state.txn_conf->keep_alive_no_activity_timeout_in;
  set_inactivity_timeout(HRTIME_SECONDS(ka_in));

  _proxy_ssn->clear_session_active();
  _proxy_ssn->ssn_last_txn_time = Thread::get_hrtime();

  super_type::release();
}

void
Http1ClientTransaction::transaction_done()
{
  if (_proxy_ssn) {
    static_cast<Http1ClientSession *>(_proxy_ssn)->release_transaction();
  }
}

bool
Http1ClientTransaction::allow_half_open() const
{
  bool config_allows_it = (_sm) ? _sm->t_state.txn_conf->allow_half_open > 0 : true;
  if (config_allows_it) {
    // Check with the session to make sure the underlying transport allows the half open scenario
    return static_cast<Http1ClientSession *>(_proxy_ssn)->allow_half_open();
  }
  return false;
}

void
Http1ClientTransaction::increment_transactions_stat()
{
  HTTP_INCREMENT_DYN_STAT(http_current_client_transactions_stat);
}

void
Http1ClientTransaction::decrement_transactions_stat()
{
  HTTP_DECREMENT_DYN_STAT(http_current_client_transactions_stat);
}
