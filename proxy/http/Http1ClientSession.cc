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

   Http1ClientSession.cc

   Description:


 ****************************************************************************/

#include <ts/ink_resolver.h>
#include "Http1ClientSession.h"
#include "HttpSM.h"
#include "HttpDebugNames.h"
#include "HttpServerSession.h"
#include "Plugin.h"

#define HttpSsnDebug(fmt, ...) SsnDebug(this, "http_cs", fmt, __VA_ARGS__)

#define STATE_ENTER(state_name, event, vio)                                                             \
  do {                                                                                                  \
    HttpSsnDebug("[%" PRId64 "] [%s, %s]", con_id, #state_name, HttpDebugNames::get_event_name(event)); \
  } while (0)


#ifdef USE_HTTP_DEBUG_LISTS

// We have debugging list that we can use to find stuck
//  client sessions
DList(Http1ClientSession, debug_link) debug_cs_list;
ink_mutex debug_cs_list_mutex;

#endif /* USE_HTTP_DEBUG_LISTS */

ClassAllocator<Http1ClientSession> http1ClientSessionAllocator("http1ClientSessionAllocator");

void
Http1ClientSession::free()
{
  super::free();
  THREAD_FREE(this, http1ClientSessionAllocator, this_thread());
}

void
Http1ClientSession::new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor)
{
  ink_assert(new_vc != nullptr);
  ink_assert(net_vc == nullptr);
  net_vc      = new_vc;
  magic          = HTTP_SSN_MAGIC_ALIVE;
  mutex          = new_vc->mutex;
  trans.mutex    = mutex; // Share this mutex with the transaction
  ssn_start_time = Thread::get_hrtime();
  in_destroy     = false;

  MUTEX_TRY_LOCK(lock, mutex, this_ethread());
  ink_assert(lock.is_locked());

  // Disable hooks for backdoor connections.
  this->hooks_on = !backdoor;

  // Unique client session identifier.
  con_id = ProxySession::next_connection_id();

  schedule_event = nullptr;

  HTTP_INCREMENT_DYN_STAT(http_current_client_connections_stat);
  conn_decrease = true;
  HTTP_INCREMENT_DYN_STAT(http_total_client_connections_stat);
  if (static_cast<HttpProxyPort::TransportType>(new_vc->attributes) == HttpProxyPort::TRANSPORT_SSL) {
    HTTP_INCREMENT_DYN_STAT(https_total_client_connections_stat);
  }

  /* inbound requests stat should be incremented here, not after the
   * header has been read */
  HTTP_INCREMENT_DYN_STAT(http_total_incoming_connections_stat);

  // check what type of socket address we just accepted
  // by looking at the address family value of sockaddr_storage
  // and logging to stat system
  switch (new_vc->get_remote_addr()->sa_family) {
  case AF_INET:
    HTTP_INCREMENT_DYN_STAT(http_total_client_connections_ipv4_stat);
    break;
  case AF_INET6:
    HTTP_INCREMENT_DYN_STAT(http_total_client_connections_ipv6_stat);
    break;
  default:
    // don't do anything if the address family is not ipv4 or ipv6
    // (there are many other address families in <sys/socket.h>
    // but we don't have a need to report on all the others today)
    break;
  }

#ifdef USE_HTTP_DEBUG_LISTS
  ink_mutex_acquire(&debug_cs_list_mutex);
  debug_cs_list.push(this);
  ink_mutex_release(&debug_cs_list_mutex);
#endif

  HttpSsnDebug("[%" PRId64 "] session born, netvc %p", con_id, new_vc);

  net_vc->set_tcp_congestion_control(CLIENT_SIDE);

  read_buffer = iobuf ? iobuf : new_MIOBuffer(HTTP_HEADER_BUFFER_SIZE_INDEX);
  buf_reader   = reader ? reader : read_buffer->alloc_reader();
  trans.set_reader(buf_reader);

  // INKqa11186: Use a local pointer to the mutex as
  // when we return from do_api_callout, the ClientSession may
  // have already been deallocated.
  EThread *ethis         = this_ethread();
  Ptr<ProxyMutex> lmutex = this->mutex;
  MUTEX_TAKE_LOCK(lmutex, ethis);
  do_api_callout(TS_HTTP_SSN_START_HOOK);
  MUTEX_UNTAKE_LOCK(lmutex, ethis);
  lmutex.clear();
}

void
Http1ClientSession::do_io_close(int alerrno)
{
  if (state == HS_CLOSED) {
    return; // Don't double call session close
  }
  if (state == HS_ACTIVE) {
    clear_session_active();
  }

  // Prevent double closing
  ink_release_assert(state != HS_CLOSED);

  // If we have an attached server session, release
  //   it back to our shared pool
  if (bound_ss) {
    dynamic_cast<HttpServerSession*>(bound_ss)->release();
    bound_ss     = nullptr;
    slave_ka_vio = nullptr;
  }
  // Completed the last transaction.  Just shutdown already
  if (transact_count == released_transactions) {
    half_close = false;
  }
  if (half_close && this->trans.get_sm()) {
    state = HS_HALF_CLOSED;
    SET_HANDLER(&Http1ClientSession::state_wait_for_close);
    HttpSsnDebug("[%" PRId64 "] session half close", con_id);

    if (net_vc) {
      // We want the client to know that that we're finished
      //  writing.  The write shutdown accomplishes this.  Unfortuantely,
      //  the IO Core semantics don't stop us from getting events
      //  on the write side of the connection like timeouts so we
      //  need to zero out the write of the continuation with
      //  the do_io_write() call (INKqa05309)
      net_vc->do_io_shutdown(IO_SHUTDOWN_WRITE);

      ka_vio = net_vc->do_io_read(this, INT64_MAX, read_buffer);
      ink_assert(slave_ka_vio != ka_vio);

      // Set the active timeout to the same as the inactive time so
      //   that this connection does not hang around forever if
      //   the ua hasn't closed
      net_vc->set_active_timeout(HRTIME_SECONDS(trans.get_sm()->t_state.txn_conf->keep_alive_no_activity_timeout_in));
    }

    // [bug 2610799] Drain any data read.
    // If the buffer is full and the client writes again, we will not receive a
    // READ_READY event.
    buf_reader->consume(buf_reader->read_avail());
  } else {
    state = HS_CLOSED;
    HttpSsnDebug("[%" PRId64 "] session closed", con_id);
    HTTP_SUM_DYN_STAT(http_transactions_per_client_con, transact_count);
    if (net_vc) {
      net_vc->do_io_close();
      net_vc = nullptr;
    }
  }
  if (transact_count == released_transactions) {
    this->destroy();
  }
}

int
Http1ClientSession::state_wait_for_close(int event, void *data)
{
  STATE_ENTER(&Http1ClientSession::state_wait_for_close, event, data);

  ink_assert(data == ka_vio);
  ink_assert(state == HS_HALF_CLOSED);

  Event *e = static_cast<Event *>(data);
  if (e == schedule_event) {
    schedule_event = nullptr;
  }

  switch (event) {
  case VC_EVENT_EOS:
  case VC_EVENT_ERROR:
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
    half_close = false;
    this->do_io_close();
    break;
  case VC_EVENT_READ_READY:
    // Drain any data read
    buf_reader->consume(buf_reader->read_avail());
    break;

  default:
    ink_release_assert(0);
    break;
  }

  return 0;
}

int
Http1ClientSession::state_slave_keep_alive(int event, void *data)
{
  STATE_ENTER(&Http1ClientSession::state_slave_keep_alive, event, data);

  ink_assert(data == slave_ka_vio);

  Event *e = static_cast<Event *>(data);
  if (e == schedule_event) {
    schedule_event = nullptr;
  }

  switch (event) {
  default:
  case VC_EVENT_READ_COMPLETE:
    // These events are bogus
    ink_assert(0);
  /* Fall Through */
  case VC_EVENT_ERROR:
  case VC_EVENT_READ_READY:
  case VC_EVENT_EOS:
    // The server session closed or something is amiss
    dynamic_cast<HttpServerSession*>(bound_ss)->do_io_close();
    bound_ss     = nullptr;
    slave_ka_vio = nullptr;
    break;

  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
    // Timeout - place the session on the shared pool
    dynamic_cast<HttpServerSession*>(bound_ss)->release();
    bound_ss     = nullptr;
    slave_ka_vio = nullptr;
    break;
  }

  return 0;
}

int
Http1ClientSession::state_keep_alive(int event, void *data)
{
  // Route the event.  It is either for client vc or
  //  the origin server slave vc
  if (data && data == slave_ka_vio) {
    return state_slave_keep_alive(event, data);
  } else {
    ink_assert(data && data == ka_vio);
    ink_assert(state == HS_KEEP_ALIVE);
  }

  STATE_ENTER(&Http1ClientSession::state_keep_alive, event, data);

  switch (event) {
  case VC_EVENT_READ_READY:
    // New transaction, need to spawn of new sm to process
    // request
    new_transaction();
    break;

  case VC_EVENT_EOS:
    this->do_io_close();
    break;

  case VC_EVENT_READ_COMPLETE:
  default:
    // These events are bogus
    ink_assert(0);
  // Fall through
  case VC_EVENT_ERROR:
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
    // Keep-alive timed out
    this->do_io_close();
    break;
  }

  return 0;
}

// Called from the Http1ClientTransaction::release
void
Http1ClientSession::release(ProxyTransaction *trans)
{
  ink_assert(state == HS_ACTIVE || state == HS_INIT);

  // Clean up the write VIO in case of inactivity timeout
  this->do_io_write(nullptr, 0, nullptr);

  // Check to see there is remaining data in the
  //  buffer.  If there is, spin up a new state
  //  machine to process it.  Otherwise, issue an
  //  IO to wait for new data
  bool more_to_read = this->buf_reader->is_read_avail_more_than(0);
  if (more_to_read) {
    trans->destroy();
    trans->set_restart_immediate(true);
    HttpSsnDebug("[%" PRId64 "] data already in buffer, starting new transaction", con_id);
    new_transaction();
  } else {
    HttpSsnDebug("[%" PRId64 "] initiating io for next header", con_id);
    trans->set_restart_immediate(false);
    state = HS_KEEP_ALIVE;
    SET_HANDLER(&Http1ClientSession::state_keep_alive);
    ka_vio = this->do_io_read(this, INT64_MAX, read_buffer);
    ink_assert(slave_ka_vio != ka_vio);

    if (net_vc) {
      net_vc->cancel_active_timeout();
      net_vc->add_to_keep_alive_queue();
    }
    trans->destroy();
  }
}

void
Http1ClientSession::attach_peer_session(ProxySession *abstract_session, bool transaction_done)
{
  HttpServerSession *ssession = dynamic_cast<HttpServerSession*>(abstract_session);
  if (ssession) {
    ink_assert(bound_ss == nullptr);
    ssession->state = HS_KA_CLIENT_SLAVE;
    bound_ss        = ssession;
    HttpSsnDebug("[%" PRId64 "] attaching server session [%" PRId64 "] as slave", con_id, ssession->connection_id());
    ink_assert(ssession->get_reader()->read_avail() == 0);
    ink_assert(ssession->get_netvc() != this->get_netvc());

    // handling potential keep-alive here
    clear_session_active();

    // Since this our slave, issue an IO to detect a close and
    //  have it call the client session back.  This IO also prevent
    //  the server net conneciton from calling back a dead sm
    SET_HANDLER(&Http1ClientSession::state_keep_alive);
    slave_ka_vio = ssession->do_io_read(this, INT64_MAX, ssession->read_buffer);
    ink_assert(slave_ka_vio != ka_vio);

    // Transfer control of the write side as well
    ssession->do_io_write(this, 0, nullptr);

    if (transaction_done) {
      ssession->get_netvc()->set_inactivity_timeout(
        HRTIME_SECONDS(trans.get_sm()->t_state.txn_conf->keep_alive_no_activity_timeout_out));
      ssession->get_netvc()->cancel_active_timeout();
    } else {
      // we are serving from the cache - this could take a while.
      ssession->get_netvc()->cancel_inactivity_timeout();
      ssession->get_netvc()->cancel_active_timeout();
    }
  } else {
    ink_assert(bound_ss != nullptr);
    bound_ss     = nullptr;
    slave_ka_vio = nullptr;
  }
}

void
Http1ClientSession::start()
{
  // Troll for data to get a new transaction
  this->release(&trans);
}
