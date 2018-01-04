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

   HttpServerSession.cc

   Description:

 ****************************************************************************/
#include "ts/ink_config.h"
#include "ts/Allocator.h"
#include "HttpServerSession.h"
#include "HttpSessionManager.h"
#include "HttpConnectionCount.h"
#include "HttpSM.h"

ClassAllocator<HttpServerSession> httpServerSessionAllocator("httpServerSessionAllocator");

void
HttpServerSession::destroy()
{
  ink_release_assert(net_vc == nullptr);
  ink_assert(read_buffer);
  ink_assert(transact_count == released_transactions);
  magic = HTTP_SSN_MAGIC_DEAD;
  if (read_buffer) {
    free_MIOBuffer(read_buffer);
    read_buffer = nullptr;
  }

  mutex.clear();
  HttpConfigParams *http_config_params = HttpConfig::acquire();
  if (static_cast<TSServerSessionSharingPoolType>(http_config_params->server_session_sharing_pool) == TS_SERVER_SESSION_SHARING_POOL_THREAD) {
    THREAD_FREE(this, httpServerSessionAllocator, this_thread());
  } else {
    httpServerSessionAllocator.free(this);
  }
}

void
HttpServerSession::new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor) 
{
  ink_assert(new_vc != nullptr);
  net_vc = new_vc;

  // Used to do e.g. mutex = new_vc->thread->mutex; when per-thread pools enabled
  mutex = new_vc->mutex;

  // Unique client session identifier.
  con_id = ProxySession::next_connection_id();

  magic = HTTP_SSN_MAGIC_ALIVE;
  HTTP_SUM_GLOBAL_DYN_STAT(http_current_server_connections_stat, 1); // Update the true global stat
  HTTP_INCREMENT_DYN_STAT(http_total_server_connections_stat);
  // Check to see if we are limiting the number of connections
  // per host
  ConnectionCount *connection_count = ConnectionCount::getInstance();
  // If the origin is in the count table, then we doing connection_limiting
  if (connection_count->getCount(get_peer_addr(), hostname_hash, sharing_match) >= 0) {
    connection_count->incrementCount(get_peer_addr(), hostname_hash, sharing_match);
    ip_port_text_buffer addrbuf;
    Debug("http_ss", "[%" PRId64 "] new connection, ip: %s, count: %u", con_id,
          ats_ip_nptop(get_peer_addr(), addrbuf, sizeof(addrbuf)),
          connection_count->getCount(get_peer_addr(), hostname_hash, sharing_match));
  }
#ifdef LAZY_BUF_ALLOC
  read_buffer = new_empty_MIOBuffer(HTTP_SERVER_RESP_HDR_BUFFER_INDEX);
#else
  read_buffer = new_MIOBuffer(HTTP_SERVER_RESP_HDR_BUFFER_INDEX);
#endif
  buf_reader = read_buffer->alloc_reader();
  trans.set_reader(buf_reader);

  Debug("http_ss", "[%" PRId64 "] session born, netvc %p", con_id, new_vc);
  state = HS_INIT;

  new_vc->set_tcp_congestion_control(SERVER_SIDE);
}

void
HttpServerSession::do_io_shutdown(ShutdownHowTo_t howto)
{
  net_vc->do_io_shutdown(howto);
}

void
HttpServerSession::do_io_close(int alerrno)
{
  Debug("http_ss", "[%" PRId64 "] session closing, netvc %p", con_id, net_vc);

  HTTP_SUM_GLOBAL_DYN_STAT(http_current_server_connections_stat, -1); // Make sure to work on the global stat
  HTTP_SUM_DYN_STAT(http_transactions_per_server_con, transact_count);

  // Check to see if we are limiting the number of connections
  // per host
  ConnectionCount *connection_count = ConnectionCount::getInstance();
  if (connection_count->getCount(get_peer_addr(), hostname_hash, sharing_match) >= 0) {
    connection_count->incrementCount(get_peer_addr(), hostname_hash, sharing_match, -1);
    ip_port_text_buffer addrbuf;
    Debug("http_ss", "[%" PRId64 "] connection closed, ip: %s, count: %u", con_id,
          ats_ip_nptop(get_peer_addr(), addrbuf, sizeof(addrbuf)),
          connection_count->getCount(get_peer_addr(), hostname_hash, sharing_match));
  } 

  if (net_vc) {
    net_vc->do_io_close(alerrno);
  }
  net_vc = nullptr;

  if (to_parent_proxy) {
    HTTP_DECREMENT_DYN_STAT(http_current_parent_proxy_connections_stat);
  }
  if (state == HS_ACTIVE) {
    HTTP_DECREMENT_DYN_STAT(http_current_server_transactions_stat);
    this->release_transaction();
  }
  destroy();
}


// void HttpServerSession::release()
//
//   Releases the session for K-A reuse
//
void
HttpServerSession::release()
{
  Debug("http_ss", "Releasing session, private_session=%d, sharing_match=%d", private_session, sharing_match);
  // Set our state to KA for stat issues
  state = HS_KA_SHARED;

  net_vc->control_flags.set_flags(0);

  // Private sessions are never released back to the shared pool
  if (private_session || TS_SERVER_SESSION_SHARING_MATCH_NONE == sharing_match) {
    this->do_io_close();
    return;
  }

  HSMresult_t r = httpSessionManager.release_session(this);

  if (r == HSM_RETRY) {
    // Session could not be put in the session manager
    //  due to lock contention
    // FIX:  should retry instead of closing
    // Make sure the vios for the current SM are cleared
    net_vc->do_io_read(nullptr, 0, nullptr);
    net_vc->do_io_write(nullptr, 0, nullptr);
    this->do_io_close();
  } else {
    // Now we need to issue a read on the connection to detect
    //  if it closes on us.  We will get called back in the
    //  continuation for this bucket, ensuring we have the lock
    //  to remove the connection from our lists
    this->do_io_read(this->allocating_pool, INT64_MAX, this->read_buffer);

    // Transfer control of the write side as well
    this->do_io_write(this->allocating_pool, 0, nullptr);

    // we probably don't need the active timeout set, but will leave it for now
    this->set_inactivity_timeout(this->get_inactivity_timeout());
    this->set_active_timeout(this->get_active_timeout());


    // The session was successfully put into the session
    //    manager and it will manage it
    // (Note: should never get HSM_NOT_FOUND here)
    ink_assert(r == HSM_DONE);
  }
}
