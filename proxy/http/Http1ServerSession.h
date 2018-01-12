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

   Http1ServerSession.h

   Description:


 ****************************************************************************/

#ifndef _HTTP_SERVER_SESSION_H_
#define _HTTP_SERVER_SESSION_H_
/* Enable LAZY_BUF_ALLOC to delay allocation of buffers until they
* are actually required.
* Enabling LAZY_BUF_ALLOC, stop Http code from allocation space
* for header buffer and tunnel buffer. The allocation is done by
* the net code in read_from_net when data is actually written into
* the buffer. By allocating memory only when it is required we can
* reduce the memory consumed by TS process.
*
* IMPORTANT NOTE: enable/disable LAZY_BUF_ALLOC in HttpSM.h as well.
*/

#include "P_Net.h"

#include "HttpProxyAPIEnums.h"
#include "Http1Session.h"
#include "PoolInterface.h"

class HttpSM;
class MIOBuffer;
class IOBufferReader;


class Http1ServerSession : public PoolInterface, public Http1Session
{
public:
  Http1ServerSession() { }

  void destroy();
  void new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor) override;

  void do_io_close(int lerrno = -1) override;
  void do_io_shutdown(ShutdownHowTo_t howto) override;

  void release(ProxyTransaction *trans) override 
  {
  }

  void attach_transaction(HttpSM *attach_sm) override
  {
    // Initialize the basic transaction object
    new_transaction();
    // Then wire it into the state machine as the server_txn
    trans.attach_transaction(attach_sm);
  }

  bool
  is_shared() const override
  {
    return state == HS_KA_SHARED;
  }

  bool
  is_active() const override
  {
    return state == HS_ACTIVE;
  }

  void set_shared() override;
private:
  Http1ServerSession(Http1ServerSession &);

};

extern ClassAllocator<Http1ServerSession> httpServerSessionAllocator;

#endif
