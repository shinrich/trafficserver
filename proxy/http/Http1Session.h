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

   Http1Session.h

   Description:

 ****************************************************************************/

#ifndef _HTTP1_SESSION_H_
#define _HTTP1_SESSION_H_

//#include "libts.h"
#include "P_Net.h"
#include "InkAPIInternal.h"
#include "HTTP.h"
#include "HttpConfig.h"
#include "IPAllow.h"
#include "ProxySession.h"
#include "Http1Transaction.h"

#ifdef USE_HTTP_DEBUG_LISTS
extern ink_mutex debug_cs_list_mutex;
#endif

class HttpSM;

enum HS_State {
  HS_INIT,
  HS_ACTIVE,
  HS_KEEP_ALIVE,
  HS_KA_CLIENT_SLAVE,
  HS_KA_SHARED,
  HS_HALF_CLOSED,
  HS_CLOSED,
};

class Http1Session : public ProxySession
{
public:
  typedef ProxySession super; ///< Parent type.
  Http1Session() {}

  // Implement ProxySession interface.
  void destroy() override;
  void free() override;
  virtual void release_transaction();

  void
  start() override
  {
    // Troll for data to get a new transaction
    this->release(&trans);
  }

  virtual void new_transaction();

  // Implement VConnection interface.
  VIO *do_io_read(Continuation *c, int64_t nbytes = INT64_MAX, MIOBuffer *buf = 0) override;
  VIO *do_io_write(Continuation *c = NULL, int64_t nbytes = INT64_MAX, IOBufferReader *buf = 0, bool owner = false) override;

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

  const char *
  get_protocol_string() const override
  {
    return "http";
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

  Http1Session(Http1Session &);

  void set_tcp_init_cwnd();

  enum {
    HTTP_SSN_MAGIC_ALIVE = 0x0123F00D,
    HTTP_SSN_MAGIC_DEAD  = 0xDEADF00D,
  };
  int magic = HTTP_SSN_MAGIC_DEAD;
  int transact_count = 0;

  IOBufferReader *buf_reader = nullptr;
  bool tcp_init_cwnd_set = false;

  int released_transactions = 0;
  bool half_close = false;
  bool conn_decrease = false;

public:
  MIOBuffer *read_buffer = nullptr;

  LINK(Http1Session, debug_link);

  Http1Transaction trans;
};

#endif
