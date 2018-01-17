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

   HttpSessionManager.cc

   Description:


 ****************************************************************************/

#include "HttpSessionManager.h"
#include "../ProxySession.h"
#include "PoolInterface.h"
#include "HttpConnectionCount.h"
#include "HttpSM.h"
#include "HttpDebugNames.h"
#include "Http1ServerSession.h"
#include "../http2/Http2ServerSession.h"

// Initialize a thread to handle HTTP session management
void
initialize_thread_for_http_sessions(EThread *thread)
{
  thread->server_session_pool = new ServerSessionPool;
}

HttpSessionManager httpSessionManager;

ServerSessionPool::ServerSessionPool() : Continuation(new_ProxyMutex()), m_ip_pool(1023), m_host_pool(1023)
{
  SET_HANDLER(&ServerSessionPool::eventHandler);
  m_ip_pool.setExpansionPolicy(IPHashTable::MANUAL);
  m_host_pool.setExpansionPolicy(HostHashTable::MANUAL);
}

void
ServerSessionPool::purge()
{
  // @c do_io_close can free the instance which clears the intrusive links and breaks the iterator.
  // Therefore @c do_io_close is called on a post-incremented iterator.
  for (IPHashTable::iterator last = m_ip_pool.end(), spot = m_ip_pool.begin(); spot != last; spot++->get_session()->do_io_close()) {
  }
  m_ip_pool.clear();
  m_host_pool.clear();
}

bool
ServerSessionPool::match(PoolInterface *ss, sockaddr const *addr, INK_MD5 const &hostname_hash,
                         TSServerSessionSharingMatchType match_style)
{
  return TS_SERVER_SESSION_SHARING_MATCH_NONE != match_style && // if no matching allowed, fail immediately.
         // The hostname matches if we're not checking it or it (and the port!) is a match.
         (TS_SERVER_SESSION_SHARING_MATCH_IP == match_style ||
          (ats_ip_port_cast(addr) == ats_ip_port_cast(ss->get_session()->get_peer_addr()) && ss->hostname_hash == hostname_hash)) &&
         // The IP address matches if we're not checking it or it is a match.
         (TS_SERVER_SESSION_SHARING_MATCH_HOST == match_style || ats_ip_addr_port_eq(ss->get_session()->get_peer_addr(), addr));
}

bool
ServerSessionPool::validate_sni(HttpSM *sm, NetVConnection *netvc)
{
  // TS-4468: If the connection matches, make sure the SNI server
  // name (if present) matches the request hostname
  int len              = 0;
  const char *req_host = sm->t_state.hdr_info.server_request.host_get(&len);
  // The sni_servername of the connection was set on HttpSM::do_http_server_open
  // by fetching the hostname from the server request.  So the connection should only
  // be reused if the hostname in the new request is the same as the host name in the
  // original request
  const char *session_sni = netvc->options.sni_servername;

  return ((sm->t_state.scheme != URL_WKSIDX_HTTPS) || !session_sni || strncasecmp(session_sni, req_host, len) == 0);
}

void
ServerSessionPool::removeSession(PoolInterface *to_remove)
{
  EThread *ethread = this_ethread();
  SCOPED_MUTEX_LOCK(lock, mutex.get(), ethread);
  HostHashTable::Location loc = m_host_pool.find(to_remove);
  HostHashTable::Location loc2 = m_host_pool.find(to_remove->hostname_hash);
  if (!loc) {
    Debug("http_ss", "Failed to find location in host list");
    if (loc2) {
      Debug("http_ss", "Found location for %p as hostname hash", to_remove);
    }
  } else {
    m_host_pool.remove(loc);
    m_ip_pool.remove(m_ip_pool.find(to_remove));
  }
}

HSMresult_t
ServerSessionPool::acquireSession(sockaddr const *addr, INK_MD5 const &hostname_hash, TSServerSessionSharingMatchType match_style,
                                  HttpSM *sm, PoolInterface *&to_return)
{
  HSMresult_t zret = HSM_NOT_FOUND;
  if (TS_SERVER_SESSION_SHARING_MATCH_HOST == match_style) {
    // This is broken out because only in this case do we check the host hash first.
    HostHashTable::Location loc = m_host_pool.find(hostname_hash);
    in_port_t port              = ats_ip_port_cast(addr);
    while (loc) { // scan for matching port.
      if (port == ats_ip_port_cast(loc->get_session()->get_peer_addr()) && validate_sni(sm, loc->get_session()->get_netvc())) {
        break;
      }
      ++loc;
    }
    if (loc) {
      to_return = loc;
      if (!to_return->allow_concurrent_transactions()) {
        m_host_pool.remove(loc);
        m_ip_pool.remove(m_ip_pool.find(loc));
      }
    }
  } else if (TS_SERVER_SESSION_SHARING_MATCH_NONE != match_style) { // matching is not disabled.
    IPHashTable::Location loc = m_ip_pool.find(addr);
    // If we're matching on the IP address we're done, this one is good enough.
    // Otherwise we need to scan further matches to match the host name as well.
    // Note we don't have to check the port because it's checked as part of the IP address key.
    if (TS_SERVER_SESSION_SHARING_MATCH_IP != match_style) {
      while (loc) {
        if (loc->hostname_hash == hostname_hash && validate_sni(sm, loc->get_session()->get_netvc())) {
          break;
        }
        ++loc;
      }
    }
    if (loc) {
      to_return = loc;
      if (!to_return->allow_concurrent_transactions()) {
        m_ip_pool.remove(loc);
        m_host_pool.remove(m_host_pool.find(loc));
      }
    }
  }
  return zret;
}

void
ServerSessionPool::releaseSession(PoolInterface *ss)
{
  if (!ss->allow_concurrent_transactions()) {
    // put it in the pools.
    m_ip_pool.insert(ss);
    m_host_pool.insert(ss);
  }
  Debug("http_ss", "[%" PRId64 "] [release session] "
                   "session placed into shared pool",
        ss->get_session()->connection_id());
}

void
ServerSessionPool::addSession(PoolInterface *ss)
{
  // put it in the pools.
  m_ip_pool.insert(ss);
  m_host_pool.insert(ss);
  Debug("http_ss", "[%" PRId64 "] [add session] "
                   "session placed into shared pool",
        ss->get_session()->connection_id());
}

//   Called from the NetProcessor to let us know that a
//    connection has closed down
//
int
ServerSessionPool::eventHandler(int event, void *data)
{
  NetVConnection *net_vc = nullptr;
  PoolInterface *s   = nullptr;

  switch (event) {
  case VC_EVENT_READ_READY:
  // The server sent us data.  This is unexpected so
  //   close the connection
  /* Fall through */
  case VC_EVENT_EOS:
  case VC_EVENT_ERROR:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ACTIVE_TIMEOUT:
    net_vc = static_cast<NetVConnection *>((static_cast<VIO *>(data))->vc_server);
    break;

  default:
    ink_release_assert(0);
    return 0;
  }

  sockaddr const *addr                 = net_vc->get_remote_addr();
  HttpConfigParams *http_config_params = HttpConfig::acquire();
  bool found                           = false;

  for (ServerSessionPool::IPHashTable::Location lh = m_ip_pool.find(addr); lh; ++lh) {
    if ((s = lh)->get_session()->get_netvc() == net_vc) {
      // if there was a timeout of some kind on a keep alive connection, and
      // keeping the connection alive will not keep us above the # of max connections
      // to the origin and we are below the min number of keep alive connections to this
      // origin, then reset the timeouts on our end and do not close the connection
      int connection_count = ConnectionCount::getInstance()->getCount(s->get_session()->get_peer_addr(), s->hostname_hash, s->sharing_match);
      if ((event == VC_EVENT_INACTIVITY_TIMEOUT || event == VC_EVENT_ACTIVE_TIMEOUT) && s->get_session()->is_shared() && connection_count >= 0) {
        bool connection_count_below_min = connection_count <= http_config_params->origin_min_keep_alive_connections;

        if (connection_count_below_min) {
          Debug("http_ss", "[%" PRId64 "] [session_bucket] session received io notice [%s], "
                           "reseting timeout to maintain minimum number of connections",
                s->get_session()->connection_id(), HttpDebugNames::get_event_name(event));
          s->get_session()->set_inactivity_timeout(s->get_session()->get_inactivity_timeout());
          s->get_session()->set_active_timeout(s->get_session()->get_active_timeout());
          found = true;
          break;
        }
      }

      // We've found our server session. Remove it from
      //   our lists and close it down
      Debug("http_ss", "[%" PRId64 "] [session_pool] session %p received io notice [%s]", s->get_session()->connection_id(), s,
            HttpDebugNames::get_event_name(event));
      ink_assert(s->get_session()->is_shared());
      // Out of the pool! Now!
      m_ip_pool.remove(lh);
      m_host_pool.remove(m_host_pool.find(s));
      // Drop connection on this end.
      s->get_session()->do_io_close();
      found = true;
      break;
    }
  }

  HttpConfig::release(http_config_params);
  if (!found) {
    // We failed to find our session.  This can only be the result of a programming flaw. Since we only ever keep
    // UnixNetVConnections and SSLNetVConnections in the session pool, the dynamic cast won't fail.
    UnixNetVConnection *unix_net_vc = dynamic_cast<UnixNetVConnection *>(net_vc);
    if (unix_net_vc) {
      char peer_ip[INET6_ADDRPORTSTRLEN];
      ats_ip_nptop(unix_net_vc->get_remote_addr(), peer_ip, sizeof(peer_ip));

      Warning("Connection leak from http keep-alive system fd=%d closed=%d peer_ip_port=%s", unix_net_vc->con.fd,
              unix_net_vc->closed, peer_ip);
    }
    ink_assert(0);
  }
  return 0;
}

void
HttpSessionManager::init()
{
  m_g_pool = new ServerSessionPool;
  eventProcessor.schedule_spawn(&initialize_thread_for_http_sessions, ET_NET);
}

// TODO: Should this really purge all keep-alive sessions?
// Does this make any sense, since we always do the global pool and not the per thread?
void
HttpSessionManager::purge_keepalives()
{
  EThread *ethread = this_ethread();

  MUTEX_TRY_LOCK(lock, m_g_pool->mutex, ethread);
  if (lock.is_locked()) {
    m_g_pool->purge();
  } // should we do something clever if we don't get the lock?
}

HSMresult_t
HttpSessionManager::acquire_session(Continuation * /* cont ATS_UNUSED */, sockaddr const *ip, const char *hostname,
                                    ProxyTransaction *ua_txn, HttpSM *sm)
{
  PoolInterface *to_return = nullptr;
  TSServerSessionSharingMatchType match_style =
    static_cast<TSServerSessionSharingMatchType>(sm->t_state.txn_conf->server_session_sharing_match);
  INK_MD5 hostname_hash;
  HSMresult_t retval = HSM_NOT_FOUND;

  ink_code_md5((unsigned char *)hostname, strlen(hostname), (unsigned char *)&hostname_hash);

  // First check to see if there is a server session bound
  //   to the user agent session
  to_return = ua_txn->get_peer_session();
  if (to_return != nullptr) {
    ua_txn->attach_peer_session(nullptr);

    // Since the client session is reusing the same server session, it seems that the SNI should match
    // Will the client make requests to different hosts over the same SSL session? Though checking
    // the IP/hostname here seems a bit redundant too
    //
    if (ServerSessionPool::match(to_return, ip, hostname_hash, match_style) &&
        ServerSessionPool::validate_sni(sm, to_return->get_session()->get_netvc())) {
      Debug("http_ss", "[%" PRId64 "] [acquire session] returning attached session ", to_return->get_session()->connection_id());
      to_return->get_session()->attach_transaction(sm);
      return HSM_DONE;
    }
    // Release this session back to the main session pool and
    //   then continue looking for one from the shared pool
    Debug("http_ss", "[%" PRId64 "] [acquire session] "
                     "session not a match, returning to shared pool",
          to_return->get_session()->connection_id());
    to_return->release();
    to_return = nullptr;
  }

  // TS-3797 Adding another scope so the pool lock is dropped after it is removed from the pool and
  // potentially moved to the current thread.  At the end of this scope, either the original
  // pool selected VC is on the current thread or its content has been moved to a new VC on the
  // current thread and the original has been deleted. This should adequately cover TS-3266 so we
  // don't have to continue to hold the pool thread while we initialize the server session in the
  // client session
  {
    // Now check to see if we have a connection in our shared connection pool
    EThread *ethread       = this_ethread();
    ProxyMutex *pool_mutex = (TS_SERVER_SESSION_SHARING_POOL_THREAD == sm->t_state.http_config_param->server_session_sharing_pool) ?
                               ethread->server_session_pool->mutex.get() :
                               m_g_pool->mutex.get();
    MUTEX_TRY_LOCK(lock, pool_mutex, ethread);
    if (lock.is_locked()) {
      if (TS_SERVER_SESSION_SHARING_POOL_THREAD == sm->t_state.http_config_param->server_session_sharing_pool) {
        retval = ethread->server_session_pool->acquireSession(ip, hostname_hash, match_style, sm, to_return);
        Debug("http_ss", "[acquire session] thread pool search %s", to_return ? "successful" : "failed");
      } else {
        retval = m_g_pool->acquireSession(ip, hostname_hash, match_style, sm, to_return);
        Debug("http_ss", "[acquire session] global pool search %s", to_return ? "successful" : "failed");
        // At this point to_return has been removed from the pool. Do we need to move it
        // to the same thread?
        if (to_return) {
          UnixNetVConnection *server_vc = dynamic_cast<UnixNetVConnection *>(to_return->get_session()->get_netvc());
          if (server_vc) {
            UnixNetVConnection *new_vc = server_vc->migrateToCurrentThread(sm, ethread);
            if (new_vc->thread != ethread) {
              // Failed to migrate, put it back to global session pool
              m_g_pool->releaseSession(to_return);
              to_return = nullptr;
              retval    = HSM_NOT_FOUND;
            } else if (new_vc != server_vc) {
              // The VC migrated, keep things from timing out on us
              new_vc->set_inactivity_timeout(new_vc->get_inactivity_timeout());
              to_return->get_session()->set_netvc(new_vc);
            } else {
              // The VC moved, keep things from timing out on us
              server_vc->set_inactivity_timeout(server_vc->get_inactivity_timeout());
            }
          }
        }
      }
    } else { // Didn't get the lock.  to_return is still NULL
      retval = HSM_RETRY;
    }
  }

  if (to_return) {
    Debug("http_ss", "[%" PRId64 "] [acquire session] return session from shared pool", to_return->get_session()->connection_id());
    // the attach_server_session will issue the do_io_read under the sm lock
    to_return->get_session()->attach_transaction(sm);
    retval = HSM_DONE;
  }
  return retval;
}

HSMresult_t
HttpSessionManager::release_session(PoolInterface *to_release)
{
  EThread *ethread = this_ethread();
  HttpConfigParams *http_config_params = HttpConfig::acquire();
  ServerSessionPool *pool =
    static_cast<TSServerSessionSharingPoolType>(http_config_params->server_session_sharing_pool) == TS_SERVER_SESSION_SHARING_POOL_THREAD ? ethread->server_session_pool : m_g_pool;
  bool released_p = true;

  to_release->set_pool(pool);

  // The per thread lock looks like it should not be needed but if it's not locked the close checking I/O op will crash.
  MUTEX_TRY_LOCK(lock, pool->mutex, ethread);
  if (lock.is_locked()) {
    pool->releaseSession(to_release);
  } else {
    Debug("http_ss", "[%" PRId64 "] [release session] could not release session due to lock contention", to_release->get_session()->connection_id());
    released_p = false;
  }

  return released_p ? HSM_DONE : HSM_RETRY;
}

HSMresult_t
HttpSessionManager::add_session(PoolInterface *to_add)
{
  EThread *ethread = this_ethread();
  HttpConfigParams *http_config_params = HttpConfig::acquire();
  ServerSessionPool *pool =
    static_cast<TSServerSessionSharingPoolType>(http_config_params->server_session_sharing_pool) == TS_SERVER_SESSION_SHARING_POOL_THREAD ? ethread->server_session_pool : m_g_pool;
  bool added_p = true;

  // The per thread lock looks like it should not be needed but if it's not locked the close checking I/O op will crash.
  MUTEX_TRY_LOCK(lock, pool->mutex, ethread);
  if (lock.is_locked()) {
    pool->addSession(to_add);
    to_add->set_pool(pool);
  } else {
    Debug("http_ss", "[%" PRId64 "] [add session] could not add session due to lock contention", to_add->get_session()->connection_id());
    added_p = false;
  }

  return added_p ? HSM_DONE : HSM_RETRY;
}

PoolInterface *
HttpSessionManager::make_session(NetVConnection *netvc, TSServerSessionSharingPoolType pool_type, TSServerSessionSharingMatchType match_type, const char *hostname, Ptr<ProxyMutex> mutex)
{
  // Figure out what protocol was negotiated
  const unsigned char *proto = nullptr;
  unsigned int proto_length = 0;
  SSLNetVConnection *sslnetvc = dynamic_cast<SSLNetVConnection*>(netvc);
  if (sslnetvc) {
    SSL_get0_alpn_selected(sslnetvc->ssl, &proto, &proto_length);
    if (proto) {
      Debug("http_ss", "[make_session] SSL negotiated protocol %.*s", proto_length, proto);
    } else {
      Debug("http_ss", "[make_session] SSL default protocol");
    }
  } else {
    Debug("http_ss", "[make_session] negotiated protocol HTTP not over SSL");
  }

  PoolInterface *retval = nullptr;
  if (proto_length == 2 && memcmp(proto, "h2", 2) == 0) {
    Http2ServerSession *session = (TS_SERVER_SESSION_SHARING_POOL_THREAD == pool_type) ?
              THREAD_ALLOC_INIT(http2ServerSessionAllocator, mutex->thread_holding) :
              http2ServerSessionAllocator.alloc();
    session->new_connection(netvc, NULL, NULL, false);
    retval = session; 
    //Debug("http_ss", "Http2 Server session not ready yet");
  } else {
    Http1ServerSession *session = (TS_SERVER_SESSION_SHARING_POOL_THREAD == pool_type) ?
              THREAD_ALLOC_INIT(httpServerSessionAllocator, mutex->thread_holding) :
              httpServerSessionAllocator.alloc();
    session->new_connection(netvc, NULL, NULL, false);
    retval = session;
  }
  retval->sharing_match = match_type;
  retval->attach_hostname(hostname);
  retval->add_session();
  return retval;
}
 
