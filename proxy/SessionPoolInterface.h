/** @file

  ProxySession - Base class for protocol client sessions.

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

#include "ProxySession.h"

class SessionPoolInterface : public ProxySession
{
  using self_type = SessionPoolInterface;

public:
  enum HSS_State {
    HSS_INIT,
    HSS_ACTIVE,
    HSS_KA_CLIENT_SLAVE,
    HSS_KA_SHARED,
  };

  /// Hash map descriptor class for IP map.
  struct IPLinkage {
    self_type *_next = nullptr;
    self_type *_prev = nullptr;

    static self_type *&next_ptr(self_type *);
    static self_type *&prev_ptr(self_type *);
    static uint32_t hash_of(sockaddr const *key);
    static sockaddr const *key_of(self_type const *ssn);
    static bool equal(sockaddr const *lhs, sockaddr const *rhs);
    // Add a couple overloads for internal convenience.
    static bool equal(sockaddr const *lhs, SessionPoolInterface const *rhs);
    static bool equal(SessionPoolInterface const *lhs, sockaddr const *rhs);
  } _ip_link;

  /// Hash map descriptor class for FQDN map.
  struct FQDNLinkage {
    self_type *_next = nullptr;
    self_type *_prev = nullptr;

    static self_type *&next_ptr(self_type *);
    static self_type *&prev_ptr(self_type *);
    static uint64_t hash_of(CryptoHash const &key);
    static CryptoHash const &key_of(self_type *ssn);
    static bool equal(CryptoHash const &lhs, CryptoHash const &rhs);
  } _fqdn_link;

  CryptoHash hostname_hash;
  HSS_State state = HSS_INIT;

  // Copy of the owning SM's server session sharing settings
  TSServerSessionSharingMatchMask sharing_match = TS_SERVER_SESSION_SHARING_MATCH_MASK_NONE;
  TSServerSessionSharingPoolType sharing_pool   = TS_SERVER_SESSION_SHARING_POOL_GLOBAL;

  // Keep track of connection limiting and a pointer to the
  // singleton that keeps track of the connection counts.
  OutboundConnTrack::Group *conn_track_group = nullptr;

  void
  set_active()
  {
    state = HSS_ACTIVE;
  }
  bool
  is_active()
  {
    return state == HSS_ACTIVE;
  }
  void
  set_private(bool new_private = true)
  {
    private_session = new_private;
  }
  bool
  is_private() const
  {
    return private_session;
  }

private:
  // Sessions become if authentication headers
  //  are sent over them
  bool private_session = false;
};

//
// LINKAGE

inline SessionPoolInterface *&
SessionPoolInterface::IPLinkage::next_ptr(self_type *ssn)
{
  return ssn->_ip_link._next;
}

inline SessionPoolInterface *&
SessionPoolInterface::IPLinkage::prev_ptr(self_type *ssn)
{
  return ssn->_ip_link._prev;
}

inline uint32_t
SessionPoolInterface::IPLinkage::hash_of(sockaddr const *key)
{
  return ats_ip_hash(key);
}

inline sockaddr const *
SessionPoolInterface::IPLinkage::key_of(self_type const *ssn)
{
  return ssn->get_remote_addr();
}

inline bool
SessionPoolInterface::IPLinkage::equal(sockaddr const *lhs, sockaddr const *rhs)
{
  return ats_ip_addr_port_eq(lhs, rhs);
}

inline bool
SessionPoolInterface::IPLinkage::equal(sockaddr const *lhs, SessionPoolInterface const *rhs)
{
  return ats_ip_addr_port_eq(lhs, key_of(rhs));
}

inline bool
SessionPoolInterface::IPLinkage::equal(SessionPoolInterface const *lhs, sockaddr const *rhs)
{
  return ats_ip_addr_port_eq(key_of(lhs), rhs);
}

inline SessionPoolInterface *&
SessionPoolInterface::FQDNLinkage::next_ptr(self_type *ssn)
{
  return ssn->_fqdn_link._next;
}

inline SessionPoolInterface *&
SessionPoolInterface::FQDNLinkage::prev_ptr(self_type *ssn)
{
  return ssn->_fqdn_link._prev;
}

inline uint64_t
SessionPoolInterface::FQDNLinkage::hash_of(CryptoHash const &key)
{
  return key.fold();
}

inline CryptoHash const &
SessionPoolInterface::FQDNLinkage::key_of(self_type *ssn)
{
  return ssn->hostname_hash;
}

inline bool
SessionPoolInterface::FQDNLinkage::equal(CryptoHash const &lhs, CryptoHash const &rhs)
{
  return lhs == rhs;
}
