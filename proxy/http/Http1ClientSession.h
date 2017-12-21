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

   Http1ClientSession.h

   Description:

 ****************************************************************************/

#ifndef _HTTP1_CLIENT_SESSION_H_
#define _HTTP1_CLIENT_SESSION_H_

//#include "libts.h"
#include "P_Net.h"
#include "InkAPIInternal.h"
#include "HTTP.h"
#include "HttpConfig.h"
#include "IPAllow.h"
#include "ProxySession.h"
#include "Http1ClientTransaction.h"

#ifdef USE_HTTP_DEBUG_LISTS
extern ink_mutex debug_cs_list_mutex;
#endif

class HttpSM;
class HttpServerSession;

enum HS_State {
  HS_INIT,
  HS_ACTIVE,
  HS_KEEP_ALIVE,
  HS_KA_CLIENT_SLAVE,
  HS_KA_SHARED,
  HS_HALF_CLOSED,
  HS_CLOSED,
};

class Http1ClientSession : public ProxySession
{
public:
  typedef ProxySession super; ///< Parent type.
  Http1ClientSession() {}

  // Implement ProxySession interface.
  void destroy() override;
  void free() override;
  void release_transaction();

  void
  start() override
  {
    // Troll for data to get a new transaction
    this->release(&trans);
  }

  void new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor);
  void new_transaction();

  // Implement VConnection interface.
  VIO *do_io_read(Continuation *c, int64_t nbytes = INT64_MAX, MIOBuffer *buf = 0) override;
  VIO *do_io_write(Continuation *c = NULL, int64_t nbytes = INT64_MAX, IOBufferReader *buf = 0, bool owner = false) override;

  void do_io_close(int lerrno = -1) override;
  void do_io_shutdown(ShutdownHowTo_t howto) override;
  void reenable(VIO *vio) override;

  void
  set_half_close_flag(bool flag)
  {
    half_close = flag;
  }

  bool
  get_half_close_flag() const
  {
    return half_close;
  }

  NetVConnection *
  get_netvc() const override
  {
    return net_vc;
  }
  void
  set_netvc(NetVConnection *netvc) override
  { 
    net_vc = netvc;
  }

  void
  release_netvc() override
  {
    // Make sure the vio's are also released to avoid
    // later surprises in inactivity timeout
    if (net_vc) {
      net_vc->do_io_read(NULL, 0, NULL);
      net_vc->do_io_write(NULL, 0, NULL);
      net_vc->set_action(NULL);
      net_vc = NULL;
    }
  }

  int
  get_transact_count() const
  {
    return transact_count;
  }

  virtual bool
  is_outbound_transparent() const
  {
    return f_outbound_transparent;
  }

  // Indicate we are done with a transaction
  virtual void release(ProxyTransaction *trans);

  virtual uint16_t
  get_outbound_port() const
  {
    return outbound_port;
  }

  virtual IpAddr
  get_outbound_ip4() const
  {
    return outbound_ip4;
  }

  virtual IpAddr
  get_outbound_ip6() const
  {
    return outbound_ip6;
  }

  virtual void attach_server_session(HttpServerSession *ssession, bool transaction_done = true);

  virtual HttpServerSession *
  get_server_session() const
  {
    return bound_ss;
  }

  void
  set_active_timeout(ink_hrtime timeout_in)
  {
    if (net_vc)
      net_vc->set_active_timeout(timeout_in);
  }

  void
  set_inactivity_timeout(ink_hrtime timeout_in)
  {
    if (net_vc)
      net_vc->set_inactivity_timeout(timeout_in);
  }

  void
  cancel_inactivity_timeout()
  {
    if (net_vc)
      net_vc->cancel_inactivity_timeout();
  }

  virtual const char *
  get_protocol_string() const
  {
    return "http";
  }

  virtual bool
  is_transparent_passthrough_allowed() const
  {
    return f_transparent_passthrough;
  }

  HS_State state = HS_INIT;

  IOBufferReader *
  get_reader()
  {
    return buf_reader;
  };

  void
  reset_read_buffer(void)
  {
    ink_assert(read_buffer->_writer);
    ink_assert(buf_reader != NULL);
    read_buffer->dealloc_all_readers();
    read_buffer->_writer = NULL;
    buf_reader           = read_buffer->alloc_reader();
  }

protected:
  NetVConnection *net_vc = NULL;

  Http1ClientSession(Http1ClientSession &);


  int state_keep_alive(int event, void *data);
  int state_slave_keep_alive(int event, void *data);
  int state_wait_for_close(int event, void *data);
  void set_tcp_init_cwnd();


  enum {
    HTTP_SSN_MAGIC_ALIVE = 0x0123F00D,
    HTTP_SSN_MAGIC_DEAD  = 0xDEADF00D,
  };
  int magic = HTTP_SSN_MAGIC_DEAD;
  int transact_count = 0;
  bool tcp_init_cwnd_set = false;
  bool half_close = false;
  bool conn_decrease = false;

  IOBufferReader *buf_reader = nullptr;


  VIO *ka_vio = nullptr;
  VIO *slave_ka_vio = nullptr;

  HttpServerSession *bound_ss = nullptr;

  int released_transactions = 0;

public:
  MIOBuffer *read_buffer = nullptr;

  // Link<Http1ClientSession> debug_link;
  LINK(Http1ClientSession, debug_link);

  /// Local address for outbound connection.
  IpAddr outbound_ip4;
  /// Local address for outbound connection.
  IpAddr outbound_ip6;
  /// Local port for outbound connection.
  uint16_t outbound_port = 0;
  /// Set outbound connection to transparent.
  bool f_outbound_transparent = false;
  /// Transparently pass-through non-HTTP traffic.
  bool f_transparent_passthrough = false;

  Http1ClientTransaction trans;
};

extern ClassAllocator<Http1ClientSession> http1ClientSessionAllocator;

#endif
