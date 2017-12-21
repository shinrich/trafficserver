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

   HttpServerSession.h

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
#define LAZY_BUF_ALLOC

#include "P_Net.h"

#include "HttpProxyAPIEnums.h"
#include "Http1ClientSession.h"

class HttpSM;
class MIOBuffer;
class IOBufferReader;


class HttpServerSession : public Http1ClientSession
{
public:
  HttpServerSession()
    : hostname_hash(),
      to_parent_proxy(false),
      private_session(false),
      sharing_match(TS_SERVER_SESSION_SHARING_MATCH_BOTH)
  {
  }

  void destroy();
  void new_connection(NetVConnection *new_vc);

  void do_io_close(int lerrno = -1) override;
  void do_io_shutdown(ShutdownHowTo_t howto) override;

  void release();
  void attach_hostname(const char *hostname);

  // Keys for matching hostnames
  IpEndpoint const &
  get_server_ip() const
  {
    ink_release_assert(net_vc != nullptr);
    return net_vc->get_remote_endpoint();
  }

  INK_MD5 hostname_hash;

  // Used to determine whether the session is for parent proxy
  // it is session to orgin server
  // We need to determine whether a closed connection was to
  // close parent proxy to update the
  // proxy.process.http.current_parent_proxy_connections
  bool to_parent_proxy;

  // Sessions become if authentication headers
  //  are sent over them
  bool private_session;

  // Copy of the owning SM's server session sharing settings
  TSServerSessionSharingMatchType sharing_match;

  LINK(HttpServerSession, ip_hash_link);
  LINK(HttpServerSession, host_hash_link);

  // The ServerSession owns the following buffer which use
  //   for parsing the headers.  The server session needs to
  //   own the buffer so we can go from a keep-alive state
  //   to being acquired and parsing the header without
  //   changing the buffer we are doing I/O on.  We can
  //   not change the buffer for I/O without issuing a
  //   an asyncronous cancel on NT
  //MIOBuffer *read_buffer;

  virtual int
  populate_protocol(ts::string_view *result, int size) const
  {
    auto vc = this->get_netvc();
    return vc ? vc->populate_protocol(result, size) : 0;
  }

  virtual const char *
  protocol_contains(ts::string_view tag_prefix) const
  {
    auto vc = this->get_netvc();
    return vc ? vc->protocol_contains(tag_prefix) : nullptr;
  }

private:
  HttpServerSession(HttpServerSession &);
};

extern ClassAllocator<HttpServerSession> httpServerSessionAllocator;

inline void
HttpServerSession::attach_hostname(const char *hostname)
{
  if (CRYPTO_HASH_ZERO == hostname_hash) {
    ink_code_md5((unsigned char *)hostname, strlen(hostname), (unsigned char *)&hostname_hash);
  }
}
#endif
