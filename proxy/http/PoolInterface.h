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

   PoolInterface.h

   Description: The ServerSession mixin class to handle session reuse pools


 ****************************************************************************/

#ifndef _POOL_INTERFACE_H_
#define _POOL_INTERFACE_H_

#include "../ProxySession.h"

class ServerSessionPool;

class PoolInterface
{
public:
  PoolInterface() { }
  virtual ~PoolInterface() {}

  void attach_hostname(const char *hostname)
  {
    if (CRYPTO_HASH_ZERO == hostname_hash) {
      ink_code_md5((unsigned char *)hostname, strlen(hostname), (unsigned char *)&hostname_hash);
    }
  }
  void release();

  void
  set_private()
  {
    private_session = true;
  }

  bool
  is_private() const
  {
    return private_session;
  }

  virtual bool
  allow_concurrent_transactions() const
  {
    return false;
  }

  void
  set_pool(ServerSessionPool *pool)
  {
     allocating_pool = pool;
  }

  // Return the session version of the object
  const ProxySession *
  get_session() const
  {
    return dynamic_cast<const ProxySession *>(this);
  }

  ProxySession *
  get_session()
  {
    return dynamic_cast<ProxySession *>(this);
  }
  
  // Add the session to the Session Manager up front if that is appropriate
  virtual void add_session() = 0;

  LINK(PoolInterface, ip_hash_link);
  LINK(PoolInterface, host_hash_link);

  // Copy of the owning SM's server session sharing settings
  TSServerSessionSharingMatchType sharing_match = TS_SERVER_SESSION_SHARING_MATCH_BOTH;

  INK_MD5 hostname_hash = CRYPTO_HASH_ZERO;

  // Used to determine whether the session is for parent proxy
  // it is session to orgin server
  // We need to determine whether a closed connection was to
  // close parent proxy to update the
  // proxy.process.http.current_parent_proxy_connections
  bool to_parent_proxy = false;

  virtual void updateAfterRelease() {};

protected: 
  ServerSessionPool *allocating_pool = nullptr;

private:
  PoolInterface(PoolInterface &);

  // Sessions become private if authentication headers
  // are sent over them
  bool private_session = false; 

};
#endif
