/** @file

  Http2ServerSession.h

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

#ifndef __HTTP2_SERVER_SESSION_H__
#define __HTTP2_SERVER_SESSION_H__

#include "Http2Session.h"
#include "../http/PoolInterface.h"

class Http2ServerSession : public Http2Session, public PoolInterface
{
public:
  typedef Http2Session super; ///< Parent type.
  typedef int (Http2ServerSession::*SessionHandler)(int, void *);

  Http2ServerSession() {}

  void free() override;
  void attach_transaction(HttpSM *attach_sm) override;
  void new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor) override;

  bool
  is_setup() const override
  {
    return setup;
  }
  
  void update() override;

  // noncopyable
  Http2ServerSession(Http2ServerSession &) = delete;
  Http2ServerSession &operator=(const Http2ServerSession &) = delete;

  // Add the session to the Session Manager up front
  // Makes sense in the Http/2 case
  void add_session() override;

  bool
  allow_concurrent_transactions() const override
  {
    return true;
  }

  void do_io_close(int lerrno = -1) override;

private:
  bool setup = true;
};

extern ClassAllocator<Http2ServerSession> http2ServerSessionAllocator;

#endif // __HTTP2_CLIENT_SESSION_H__
