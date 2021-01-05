/** @file

  Http2ServerSession.

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

#pragma once

#include "Plugin.h"
#include "Http2CommonSession.h"
#include <string_view>
#include "tscore/ink_inet.h"
#include "tscore/History.h"
#include "Milestones.h"
#include "PoolableSession.h"

class Http2ServerSession : public PoolableSession, public Http2CommonSession
{
public:
  using super          = PoolableSession; ///< Parent type.
  using SessionHandler = int (Http2ServerSession::*)(int, void *);

  Http2ServerSession();

  /////////////////////
  // Methods

  // Implement VConnection interface
  void do_io_close(int lerrno = -1) override;

  // Implement ProxySession interface
  void new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader) override;
  void start() override;
  void destroy() override;
  void release(ProxyTransaction *trans) override;
  void free() override;
  ProxyTransaction *new_transaction() override;
  bool ready_to_write() const override;
  void received_setting() override;

  void add_session();
  void remove_session();

  ////////////////////
  // Accessors
  sockaddr const *get_remote_addr() const override;
  sockaddr const *get_local_addr() override;
  int get_transact_count() const override;
  const char *get_protocol_string() const override;
  int populate_protocol(std::string_view *result, int size) const override;
  const char *protocol_contains(std::string_view prefix) const override;
  void increment_current_active_connections_stat() override;
  void decrement_current_active_connections_stat() override;

  ProxySession *get_proxy_session() override;

  void set_upgrade_context(HTTPHdr *h);
  const Http2UpgradeContext &get_upgrade_context() const;

  // noncopyable
  Http2ServerSession(Http2ServerSession &) = delete;
  Http2ServerSession &operator=(const Http2ServerSession &) = delete;

  bool is_multiplexing() const override;

private:
  int main_event_handler(int, void *);

  IpEndpoint cached_client_addr;
  IpEndpoint cached_local_addr;

  bool _received_setting = false;

  // For Upgrade: h2c
  Http2UpgradeContext upgrade_context;
};

extern ClassAllocator<Http2ServerSession> http2ServerSessionAllocator;

///////////////////////////////////////////////
// INLINE

inline const Http2UpgradeContext &
Http2ServerSession::get_upgrade_context() const
{
  return upgrade_context;
}
