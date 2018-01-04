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
#include "Http1Session.h"

#ifdef USE_HTTP_DEBUG_LISTS
extern ink_mutex debug_cs_list_mutex;
#endif

class HttpSM;
class HttpServerSession;
class ProxyTransaction;

class Http1ClientSession : public Http1Session
{
public:
  typedef Http1Session super; ///< Parent type.
  Http1ClientSession() {}

  // Implement ProxySession interface.
  void free() override;

  void start() override;

  void new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor);

  // Indicate we are done with a transaction
  virtual void release(ProxyTransaction *trans);

  virtual bool
  is_outbound_transparent() const
  {
    return f_outbound_transparent;
  }

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

  ProxySession * const
  get_peer_session() const override
  {
    return bound_ss;
  }

  virtual bool
  is_transparent_passthrough_allowed() const
  {
    return f_transparent_passthrough;
  }

  // Unique per client to clean up bound server sessions appropriately
  void do_io_close(int lerrno = -1) override;

  void
  new_transaction() override
  {
    super::new_transaction();
    trans.new_transaction();
  }

protected:
  Http1ClientSession(Http1ClientSession &);


  int state_keep_alive(int event, void *data);
  int state_slave_keep_alive(int event, void *data);
  int state_wait_for_close(int event, void *data);


  VIO *ka_vio = nullptr;
  VIO *slave_ka_vio = nullptr;

  ProxySession *bound_ss = nullptr;

public:
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

};

extern ClassAllocator<Http1ClientSession> http1ClientSessionAllocator;

#endif
