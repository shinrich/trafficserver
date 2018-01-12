/** @file

  Http2ClientSession.h

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

#ifndef __HTTP2_CLIENT_SESSION_H__
#define __HTTP2_CLIENT_SESSION_H__

#include "Http2Session.h"

class Http2ClientSession : public Http2Session
{
public:
  typedef Http2Session super; ///< Parent type.
  typedef int (Http2ClientSession::*SessionHandler)(int, void *);

  Http2ClientSession() {}

  void free() override;

  // noncopyable
  Http2ClientSession(Http2ClientSession &) = delete;
  Http2ClientSession &operator=(const Http2ClientSession &) = delete;

private:
};

extern ClassAllocator<Http2ClientSession> http2ClientSessionAllocator;

#endif // __HTTP2_CLIENT_SESSION_H__
