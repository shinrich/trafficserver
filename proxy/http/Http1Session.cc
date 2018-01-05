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

/****************************************************************************

   Http1Session.cc

   Description:


 ****************************************************************************/

#include <ts/ink_resolver.h>
#include "Http1Session.h"
#include "Http1Transaction.h"
#include "HttpSM.h"
#include "HttpDebugNames.h"
#include "HttpServerSession.h"
#include "Plugin.h"

#define HttpSsnDebug(fmt, ...) SsnDebug(this, "http_cs", fmt, __VA_ARGS__)

#define STATE_ENTER(state_name, event, vio)                                                             \
  do {                                                                                                  \
    HttpSsnDebug("[%" PRId64 "] [%s, %s]", con_id, #state_name, HttpDebugNames::get_event_name(event)); \
  } while (0)


void
Http1Session::destroy()
{
  if (state != HS_CLOSED) {
    return;
  }
  if (!in_destroy) {
    in_destroy = true;

    HttpSsnDebug("[%" PRId64 "] session destroy", con_id);
    ink_release_assert(!net_vc);
    ink_assert(read_buffer);
    ink_release_assert(transact_count == released_transactions);
    do_api_callout(TS_HTTP_SSN_CLOSE_HOOK);
  } else {
    Warning("http1: Attempt to double ssn close");
  }
}

void
Http1Session::release_transaction()
{
  released_transactions++;
  trans.attach_transaction(nullptr);
  ink_assert(released_transactions <= transact_count);
}

void
Http1Session::free()
{
  magic = HTTP_SSN_MAGIC_DEAD;
  if (read_buffer) {
    free_MIOBuffer(read_buffer);
    read_buffer = nullptr;
  }

#ifdef USE_HTTP_DEBUG_LISTS
  ink_mutex_acquire(&debug_cs_list_mutex);
  debug_cs_list.remove(this);
  ink_mutex_release(&debug_cs_list_mutex);
#endif

  if (conn_decrease) {
    HTTP_DECREMENT_DYN_STAT(http_current_client_connections_stat);
    conn_decrease = false;
  }

  // Clean up the write VIO in case of inactivity timeout
  this->do_io_write(nullptr, 0, nullptr);

  // Free the transaction resources
  this->trans.super::destroy();

  super::free();
}

VIO *
Http1Session::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  return net_vc->do_io_read(c, nbytes, buf);
}

VIO *
Http1Session::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner)
{
  /* conditionally set the tcp initial congestion window
     before our first write. */
  HttpSsnDebug("tcp_init_cwnd_set %d", (int)tcp_init_cwnd_set);
  if (!tcp_init_cwnd_set) {
    tcp_init_cwnd_set = true;
    set_tcp_init_cwnd();
  }
  if (net_vc) {
    return net_vc->do_io_write(c, nbytes, buf, owner);
  } else {
    return nullptr;
  }
}

void
Http1Session::set_tcp_init_cwnd()
{
  if (!trans.get_sm()) {
    return;
  }
  int desired_tcp_init_cwnd = trans.get_sm()->t_state.txn_conf->server_tcp_init_cwnd;
  HttpSsnDebug("desired TCP congestion window is %d", desired_tcp_init_cwnd);
  if (desired_tcp_init_cwnd == 0) {
    return;
  }
  if (get_netvc()->set_tcp_init_cwnd(desired_tcp_init_cwnd) != 0) {
    HttpSsnDebug("set_tcp_init_cwnd(%d) failed", desired_tcp_init_cwnd);
  }
}

void
Http1Session::do_io_shutdown(ShutdownHowTo_t howto)
{
  net_vc->do_io_shutdown(howto);
}

void
Http1Session::reenable(VIO *vio)
{
  net_vc->reenable(vio);
}

void
Http1Session::new_transaction()
{
  // If the client connection terminated during API callouts we're done.
  if (nullptr == net_vc) {
    this->do_io_close(); // calls the SSN_CLOSE hooks to match the SSN_START hooks.
    return;
  }

  // Defensive programming, make sure nothing persists across
  // connection re-use
  half_close = false;

  state = HS_ACTIVE;

  trans.set_parent(this);
  transact_count++;

  net_vc->add_to_active_queue();
}

