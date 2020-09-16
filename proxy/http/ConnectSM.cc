/** @file

  HTTP Connect state machine

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

#include "HttpSM.h"
#include "tscore/ink_assert.h"
#include "HttpDebugNames.h"
#include "ts/sdt.h"
#include "PluginVC.h"
#include "HttpSessionManager.h"
#include "Http1ServerSession.h"

void
ConnectAction::cancel(Continuation *c)
{
  ink_assert(this->cancelled == 0);

  this->cancelled = 1;
  sm->cancel_pending_action();
}

static void
set_tls_options(NetVCOptions &opt, const OverridableHttpConfigParams *txn_conf)
{
  char *verify_server = nullptr;
  if (txn_conf->ssl_client_verify_server_policy == nullptr) {
    opt.verifyServerPolicy = YamlSNIConfig::Policy::UNSET;
  } else {
    verify_server = txn_conf->ssl_client_verify_server_policy;
    if (strcmp(verify_server, "DISABLED") == 0) {
      opt.verifyServerPolicy = YamlSNIConfig::Policy::DISABLED;
    } else if (strcmp(verify_server, "PERMISSIVE") == 0) {
      opt.verifyServerPolicy = YamlSNIConfig::Policy::PERMISSIVE;
    } else if (strcmp(verify_server, "ENFORCED") == 0) {
      opt.verifyServerPolicy = YamlSNIConfig::Policy::ENFORCED;
    } else {
      Warning("%s is invalid for proxy.config.ssl.client.verify.server.policy.  Should be one of DISABLED, PERMISSIVE, or ENFORCED",
              verify_server);
      opt.verifyServerPolicy = YamlSNIConfig::Policy::UNSET;
    }
  }
  if (txn_conf->ssl_client_verify_server_properties == nullptr) {
    opt.verifyServerProperties = YamlSNIConfig::Property::UNSET;
  } else {
    verify_server = txn_conf->ssl_client_verify_server_properties;
    if (strcmp(verify_server, "SIGNATURE") == 0) {
      opt.verifyServerProperties = YamlSNIConfig::Property::SIGNATURE_MASK;
    } else if (strcmp(verify_server, "NAME") == 0) {
      opt.verifyServerProperties = YamlSNIConfig::Property::NAME_MASK;
    } else if (strcmp(verify_server, "ALL") == 0) {
      opt.verifyServerProperties = YamlSNIConfig::Property::ALL_MASK;
    } else if (strcmp(verify_server, "NONE") == 0) {
      opt.verifyServerProperties = YamlSNIConfig::Property::NONE;
    } else {
      Warning("%s is invalid for proxy.config.ssl.client.verify.server.properties.  Should be one of SIGNATURE, NAME, or ALL",
              verify_server);
      opt.verifyServerProperties = YamlSNIConfig::Property::NONE;
    }
  }
}

bool
ConnectSM::is_private() const
{
  bool res = false;
  if (_server_txn) {
    res = static_cast<PoolableSession*>(_server_txn->get_proxy_ssn())->is_private();
  } else if (_root_sm->ua_txn) {
    Http1ServerSession *ss = dynamic_cast<Http1ServerSession *>(_root_sm->ua_txn->get_server_session());
    if (ss) {
      res = ss->is_private();
    } else if (will_be_private_ss) {
      res = will_be_private_ss;
    }
  }
  return res;
}

Action *
ConnectSM::acquire_txn(HttpSM *sm, bool raw)
{
  HttpTransact::State &s = sm->t_state;
  int ip_family = s.current.server->dst_addr.sa.sa_family;
  auto fam_name = ats_ip_family_name(ip_family);
  Debug("http_connect", "entered inside acquire_txn [%.*s]", static_cast<int>(fam_name.size()), fam_name.data());

  this->_pending_action = nullptr;

  // Clean up connection tracking info if any. Need to do it now so the selected group
  // is consistent with the actual upstream in case of retry.
  s.outbound_conn_track_state.clear();

  if (false == s.api_server_addr_set) {
    ink_assert(s.current.server->dst_addr.host_order_port() > 0);
  } else {
    ink_assert(s.current.server->dst_addr.port() != 0); // verify the plugin set it to something.
  }

  char addrbuf[INET6_ADDRPORTSTRLEN];
  Debug("http_connect", "[%" PRId64 "] open connection to %s: %s", _root_sm->sm_id, s.current.server->name,
          ats_ip_nptop(&s.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)));

  if (sm->plugin_tunnel) {
    PluginVCCore *t           = sm->plugin_tunnel;
    sm->plugin_tunnel         = nullptr;
    Action *pvc_action_handle = t->connect_re(this);

    // This connect call is always reentrant
    ink_release_assert(pvc_action_handle == ACTION_RESULT_DONE);
    this->_return_state = Tunnel;
    return pvc_action_handle;
  }

  Debug("http_connect", "[ConnectSM::acquire_txn] Sending request to server");

  sm->milestones[TS_MILESTONE_SERVER_CONNECT] = Thread::get_hrtime();
  if (sm->milestones[TS_MILESTONE_SERVER_FIRST_CONNECT] == 0) {
    sm->milestones[TS_MILESTONE_SERVER_FIRST_CONNECT] = sm->milestones[TS_MILESTONE_SERVER_CONNECT];
  }

  // Check for remap rule. If so, only apply ip_allow filter if it is activated (ip_allow_check_enabled_p set).
  // Otherwise, if no remap rule is defined, apply the ip_allow filter.
  if (!s.url_remap_success || s.url_map.getMapping()->ip_allow_check_enabled_p) {
    // Method allowed on dest IP address check
    sockaddr *server_ip    = &s.current.server->dst_addr.sa;
    IpAllow::ACL acl       = IpAllow::match(server_ip, IpAllow::DST_ADDR);
    bool deny_request      = false; // default is fail open.
    int method             = s.hdr_info.server_request.method_get_wksidx();
    int method_str_len     = 0;
    const char *method_str = nullptr;

    if (acl.isValid()) {
      if (acl.isDenyAll()) {
        deny_request = true;
      } else if (!acl.isAllowAll()) {
        if (method != -1) {
          deny_request = !acl.isMethodAllowed(method);
        } else {
          method_str   = s.hdr_info.server_request.method_get(&method_str_len);
          deny_request = !acl.isNonstandardMethodAllowed(std::string_view(method_str, method_str_len));
        }
      }
    }

    if (deny_request) {
      if (is_debug_tag_set("ip-allow")) {
        ip_text_buffer ipb;
        if (method != -1) {
          method_str     = hdrtoken_index_to_wks(method);
          method_str_len = strlen(method_str);
        } else if (!method_str) {
          method_str = s.hdr_info.client_request.method_get(&method_str_len);
        }
        Warning("server '%s' prohibited by ip-allow policy at line %d", ats_ip_ntop(server_ip, ipb, sizeof(ipb)),
                acl.source_line());
        Debug("ip-allow", "Line %d denial for '%.*s' from %s", acl.source_line(), method_str_len, method_str,
              ats_ip_ntop(server_ip, ipb, sizeof(ipb)));
      }
      s.current.attempts = s.txn_conf->connect_attempts_max_retries; // prevent any more retries with this IP
      // call_transact_and_set_next_state(HttpTransact::Forbidden);
      this->_return_state = ErrorForbid;
      return ACTION_RESULT_DONE;
    }
  }

  // If this is not a raw connection, we try to get a session from the
  //  shared session pool.  Raw connections are for SSLs tunnel and
  //  require a new connection
  //

  // This problem with POST requests is a bug.  Because of the issue of the
  // race with us sending a request after server has closed but before the FIN
  // gets to us, we should open a new connection for POST.  I believe TS used
  // to do this but as far I can tell the code that prevented keep-alive if
  // there is a request body has been removed.

  // If we are sending authorizations headers, mark the connection private
  //
  // We do this here because it means that we will not waste a connection from the pool if we already
  // know that the session will be private. This is overridable meaning that if a plugin later decides
  // it shouldn't be private it can still be returned to a shared pool.
  //
  if (s.txn_conf->auth_server_session_private == 1 &&
      s.hdr_info.server_request.presence(MIME_PRESENCE_AUTHORIZATION | MIME_PRESENCE_PROXY_AUTHORIZATION |
                                         MIME_PRESENCE_WWW_AUTHENTICATE)) {
    Debug("http_ss_auth", "Setting server session to private for authorization header");
    this->will_be_private_ss = true;
  }

  if (s.method == HTTP_WKSIDX_POST || s.method == HTTP_WKSIDX_PUT) {
    // don't share the session if keep-alive for post is not on
    if (s.txn_conf->keep_alive_post_out == 0) {
      Debug("http_ss", "Setting server session to private because of keep-alive post out");
      this->will_be_private_ss = true;
    }
  }

#ifdef OLD // Should it be possible that _server_txn is already set?
  // If there is already an attached server session mark it as private.
  if (_server_txn != nullptr && will_be_private_ss) {
    static_cast<PoolableSession*>(_server_txn->get_proxy_ssn())->set_private();
  }
#endif

  if ((raw == false) && TS_SERVER_SESSION_SHARING_MATCH_NONE != s.txn_conf->server_session_sharing_match &&
      (s.txn_conf->keep_alive_post_out == 1 || s.hdr_info.request_content_length == 0) && !is_private() &&
      sm->ua_txn != nullptr) {
    HSMresult_t shared_result;
    shared_result = httpSessionManager.acquire_session(this,                                 // state machine
                                                       &s.current.server->dst_addr.sa, // ip + port
                                                       s.current.server->name,         // hostname
                                                       sm->ua_txn,                               // has ptr to bound ua sessions
                                                       sm                                  // sm
    );

    switch (shared_result) {
    case HSM_DONE:
      ink_release_assert(_server_txn != nullptr);
      _return_state = ServerTxnCreated;
      //handle_http_server_open();
      return ACTION_RESULT_DONE;
    case HSM_NOT_FOUND:
      ink_release_assert(_server_txn == nullptr);
      break;
    case HSM_RETRY:
      //  Could not get shared pool lock
      //   FIX: should retry lock
      break;
    default:
      ink_release_assert(0);
    }
  }
  // Avoid a problem where server session sharing is disabled and we have keep-alive, we are trying to open a new server
  // session when we already have an attached server session.
  else if ((TS_SERVER_SESSION_SHARING_MATCH_NONE == s.txn_conf->server_session_sharing_match || is_private()) &&
           (ua_txn != nullptr)) {
    PoolableSession *existing_ss = sm->ua_txn->get_server_session();

    if (existing_ss) {
      // [amc] Not sure if this is the best option, but we don't get here unless session sharing is disabled
      // so there's no point in further checking on the match or pool values. But why check anything? The
      // client has already exchanged a request with this specific origin server and has sent another one
      // shouldn't we just automatically keep the association?
      if (ats_ip_addr_port_eq(existing_ss->get_remote_addr(), &s.current.server->dst_addr.sa)) {
        sm->ua_txn->attach_server_session(nullptr);
        existing_ss->set_active();
        sm->attach_server_session(existing_ss);
        ink_release_assert(_server_txn != nullptr);
        //handle_http_server_open();
        _return_state = ServerTxnCreated;
        return ACTION_RESULT_DONE;
      } else {
        // As this is in the non-sharing configuration, we want to close
        // the existing connection and call connect_re to get a new one
        existing_ss->set_inactivity_timeout(HRTIME_SECONDS(s.txn_conf->keep_alive_no_activity_timeout_out));
        existing_ss->release(_server_txn);
        sm->ua_txn->attach_server_session(nullptr);
      }
    }
  }
  // Otherwise, we release the existing connection and call connect_re
  // to get a new one.
  // ua_txn is null when s.req_flavor == REQ_FLAVOR_SCHEDULED_UPDATE
  else if (sm->ua_txn != nullptr) {
    PoolableSession *existing_ss = ua_txn->get_server_session();
    if (existing_ss) {
      existing_ss->set_inactivity_timeout(HRTIME_SECONDS(s.txn_conf->keep_alive_no_activity_timeout_out));
      existing_ss->release(_server_txn);
      sm->ua_txn->attach_server_session(nullptr);
    }
  }
  // Check to see if we have reached the max number of connections.
  // Atomically read the current number of connections and check to see
  // if we have gone above the max allowed.
  if (s.http_config_param->server_max_connections > 0) {
    int64_t sum;

    HTTP_READ_GLOBAL_DYN_SUM(http_current_server_connections_stat, sum);

    // Note that there is a potential race condition here where
    // the value of the http_current_server_connections_stat gets changed
    // between the statement above and the check below.
    // If this happens, we might go over the max by 1 but this is ok.
    if (sum >= s.http_config_param->server_max_connections) {
      httpSessionManager.purge_keepalives();
      // Eventually may want to have a queue as the origin_max_connection does to allow for a combination
      // of retries and errors.  But at this point, we are just going to allow the error case.
      s.current.state = HttpTransact::CONNECTION_ERROR;
      //call_transact_and_set_next_state(HttpTransact::HandleResponse);
      this->_return_state = ErrorResponse;
      return ACTION_RESULT_DONE;
    }
  }

  // See if the outbound connection tracker data is needed. If so, get it here for consistency.
  if (s.txn_conf->outbound_conntrack.max > 0 || s.txn_conf->outbound_conntrack.min > 0) {
    s.outbound_conn_track_state = OutboundConnTrack::obtain(
      s.txn_conf->outbound_conntrack, std::string_view{s.current.server->name}, s.current.server->dst_addr);
  }

  // Check to see if we have reached the max number of connections on this upstream host.
  if (s.txn_conf->outbound_conntrack.max > 0) {
    auto &ct_state = s.outbound_conn_track_state;
    auto ccount    = ct_state.reserve();
    if (ccount > s.txn_conf->outbound_conntrack.max) {
      ct_state.release();

      ink_assert(_pending_action == nullptr); // in case of reschedule must not have already pending.

      // If the queue is disabled, reschedule.
      if (s.http_config_param->outbound_conntrack.queue_size < 0) {
        ct_state.enqueue();
        ct_state.rescheduled();
        _pending_action =
          eventProcessor.schedule_in(this, HRTIME_MSECONDS(s.http_config_param->outbound_conntrack.queue_delay.count()));
      } else if (s.http_config_param->outbound_conntrack.queue_size > 0) { // queue enabled, check for a slot
        auto wcount = ct_state.enqueue();
        if (wcount < s.http_config_param->outbound_conntrack.queue_size) {
          ct_state.rescheduled();
          Debug("http_connect", "%s", lbw().print("[{}] queued for {}\0", sm->sm_id, s.current.server->dst_addr).data());
          _pending_action =
            eventProcessor.schedule_in(this, HRTIME_MSECONDS(s.http_config_param->outbound_conntrack.queue_delay.count()));
        } else {              // the queue is full
          ct_state.dequeue(); // release the queue slot
          ct_state.blocked(); // note the blockage.
          //HTTP_INCREMENT_DYN_STAT(http_origin_connections_throttled_stat);
          //send_origin_throttled_response();
        }
      } else { // queue size is 0, always block.
        ct_state.blocked();
        //HTTP_INCREMENT_DYN_STAT(http_origin_connections_throttled_stat);
        //send_origin_throttled_response();
      }

      ct_state.Warn_Blocked(&s.txn_conf->outbound_conntrack, _root_sm->sm_id, ccount - 1, &s.current.server->dst_addr.sa,
                            debug_on && is_debug_tag_set("http") ? "http" : nullptr);

      if (_pending_action) {
        return &_captive_action;
      }  else {
        _return_state = ErrorThrottle;
        return ACTION_RESULT_DONE;
      }
    } else {
      ct_state.Note_Unblocked(&s.txn_conf->outbound_conntrack, ccount, &s.current.server->dst_addr.sa);
    }

    ct_state.update_max_count(ccount);
  }

  // We did not manage to get an existing session and need to open a new connection
  Action *connect_action_handle;

  NetVCOptions opt;
  opt.f_blocking_connect = false;
  opt.set_sock_param(s.txn_conf->sock_recv_buffer_size_out, s.txn_conf->sock_send_buffer_size_out,
                     s.txn_conf->sock_option_flag_out, s.txn_conf->sock_packet_mark_out,
                     s.txn_conf->sock_packet_tos_out);

  set_tls_options(opt, s.txn_conf);

  opt.ip_family = ip_family;

  int scheme_to_use = s.scheme; // get initial scheme
  bool tls_upstream = scheme_to_use == URL_WKSIDX_HTTPS;
  if (sm->ua_txn) {
    if (raw) {
      SSLNetVConnection *ssl_vc = dynamic_cast<SSLNetVConnection *>(sm->ua_txn->get_netvc());
      if (ssl_vc) {
        tls_upstream = ssl_vc->upstream_tls();
      }
    }
    opt.local_port = sm->ua_txn->get_outbound_port();

    const IpAddr &outbound_ip = AF_INET6 == opt.ip_family ? sm->ua_txn->get_outbound_ip6() : sm->ua_txn->get_outbound_ip4();
    if (outbound_ip.isValid()) {
      opt.addr_binding = NetVCOptions::INTF_ADDR;
      opt.local_ip     = outbound_ip;
    } else if (sm->ua_txn->is_outbound_transparent()) {
      opt.addr_binding = NetVCOptions::FOREIGN_ADDR;
      opt.local_ip     = s.client_info.src_addr;
      /* If the connection is server side transparent, we can bind to the
         port that the client chose instead of randomly assigning one at
         the proxy.  This is controlled by the 'use_client_source_port'
         configuration parameter.
      */

      NetVConnection *client_vc = sm->ua_txn->get_netvc();
      if (s.http_config_param->use_client_source_port && nullptr != client_vc) {
        opt.local_port = client_vc->get_remote_port();
      }
    }
  }

  if (!s.is_websocket) { // if not websocket, then get scheme from server request
    int new_scheme_to_use = s.hdr_info.server_request.url_get()->scheme_get_wksidx();
    // if the server_request url scheme was never set, try the client_request
    if (new_scheme_to_use < 0) {
      new_scheme_to_use = s.hdr_info.client_request.url_get()->scheme_get_wksidx();
    }
    if (new_scheme_to_use >= 0) { // found a new scheme, use it
      scheme_to_use = new_scheme_to_use;
    }
    if (!raw || !tls_upstream) {
      tls_upstream = scheme_to_use == URL_WKSIDX_HTTPS;
    }
  }

  // draft-stenberg-httpbis-tcp recommends only enabling TFO on indempotent methods or
  // those with intervening protocol layers (eg. TLS).

  if (tls_upstream || HttpTransactHeaders::is_method_idempotent(s.method)) {
    opt.f_tcp_fastopen = (s.txn_conf->sock_option_flag_out & NetVCOptions::SOCK_OPT_TCP_FAST_OPEN);
  }

  opt.ssl_client_cert_name        = s.txn_conf->ssl_client_cert_filename;
  opt.ssl_client_private_key_name = s.txn_conf->ssl_client_private_key_filename;
  opt.ssl_client_ca_cert_name     = s.txn_conf->ssl_client_ca_cert_filename;

  if (raw) {
    SET_HANDLER(&ConnectSM::state_http_server_raw_open);
  } else {
    SET_HANDLER(&ConnectSM::state_http_server_open);
  }

  if (tls_upstream) {
    Debug("http_connect", "calling sslNetProcessor.connect_re");

    std::string_view sni_name = sm->get_outbound_sni();
    if (sni_name.length() > 0) {
      opt.set_sni_servername(sni_name.data(), sni_name.length());
    }
    int len = 0;
    if (s.txn_conf->ssl_client_sni_policy != nullptr &&
        !strcmp(s.txn_conf->ssl_client_sni_policy, "verify_with_name_source")) {
      // also set sni_hostname with host header from server request in this policy
      const char *host = s.hdr_info.server_request.host_get(&len);
      if (host && len > 0) {
        opt.set_sni_hostname(host, len);
      }
    }
    if (s.server_info.name) {
      opt.set_ssl_servername(s.server_info.name);
    }

    connect_action_handle = sslNetProcessor.connect_re(this,                                 // state machine
                                                &s.current.server->dst_addr.sa, // addr + port
                                                &opt);
  } else {
    Debug("http_connect", "calling netProcessor.connect_re");
    connect_action_handle = netProcessor.connect_re(this,                                 // state machine
                                                    &s.current.server->dst_addr.sa, // addr + port
                                                    &opt);
  }

  if (connect_action_handle != ACTION_RESULT_DONE) {
    ink_assert(!_pending_action);
    _pending_action = connect_action_handle;
    return &_captive_action;
  } else {
    _return_state = ServerTxnCreated;
    return connect_action_handle;
  }
}

int
ConnectSM::state_http_server_open(int event, void *data)
{
  HttpTransact::State &s = _root_sm->t_state;
  Debug("http_connect", "entered inside state_http_server_open");
  //STATE_ENTER(&HttpSM::state_http_server_open, event);
  ink_release_assert(event == EVENT_INTERVAL || event == NET_EVENT_OPEN || event == NET_EVENT_OPEN_FAILED ||
                     _pending_action == nullptr);
  if (event != NET_EVENT_OPEN) {
    _pending_action = nullptr;
  }
  _root_sm->milestones[TS_MILESTONE_SERVER_CONNECT_END] = Thread::get_hrtime();
  NetVConnection *netvc                       = nullptr;

  switch (event) {
  case NET_EVENT_OPEN: {
    Http1ServerSession *session =
      (TS_SERVER_SESSION_SHARING_POOL_THREAD == s.http_config_param->server_session_sharing_pool) ?
        THREAD_ALLOC_INIT(httpServerSessionAllocator, mutex->thread_holding) :
        httpServerSessionAllocator.alloc();
    session->sharing_pool  = static_cast<TSServerSessionSharingPoolType>(s.http_config_param->server_session_sharing_pool);
    session->sharing_match = static_cast<TSServerSessionSharingMatchMask>(s.txn_conf->server_session_sharing_match);

    netvc = static_cast<NetVConnection *>(data);
    session->attach_hostname(s.current.server->name);
    UnixNetVConnection *vc = static_cast<UnixNetVConnection *>(data);
    // Since the UnixNetVConnection::action_ or SocksEntry::action_ may be returned from netProcessor.connect_re, and the
    // SocksEntry::action_ will be copied into UnixNetVConnection::action_ before call back NET_EVENT_OPEN from SocksEntry::free(),
    // so we just compare the Continuation between pending_action and VC's action_.
    ink_release_assert(_pending_action == nullptr || _pending_action->continuation == vc->get_action()->continuation);
    _pending_action = nullptr;

    session->new_connection(vc, nullptr, nullptr);

    ATS_PROBE1(new_origin_server_connection, s.current.server->name);

    session->set_active();
    ats_ip_copy(&s.server_info.src_addr, netvc->get_local_addr());

    // If origin_max_connections or origin_min_keep_alive_connections is set then we are metering
    // the max and or min number of connections per host. Transfer responsibility for this to the
    // session object.
    if (s.outbound_conn_track_state.is_active()) {
      Debug("http_connect", "[%" PRId64 "] max number of outbound connections: %d", _root_sm->sm_id, s.txn_conf->outbound_conntrack.max);
      session->enable_outbound_connection_tracking(s.outbound_conn_track_state.drop());
    }

    this->attach_server_session(session);
    if (s.current.request_to == HttpTransact::PARENT_PROXY) {
      session->to_parent_proxy = true;
      HTTP_INCREMENT_DYN_STAT(http_current_parent_proxy_connections_stat);
      HTTP_INCREMENT_DYN_STAT(http_total_parent_proxy_connections_stat);

    } else {
      session->to_parent_proxy = false;
    }
    if (plugin_tunnel_type == HTTP_NO_PLUGIN_TUNNEL) {
      Debug("http_connect", "[%" PRId64 "] setting handler for TCP handshake", _root_sm->sm_id);
      // Just want to get a write-ready event so we know that the TCP handshake is complete.
      _server_txn->handler = &ConnectSM::state_http_server_open;
      _server_txn->do_io_write(this, 1, _server_txn->get_reader());
    } else { // in the case of an intercept plugin don't to the connect timeout change
      Debug("http_connect", "[%" PRId64 "] not setting handler for TCP handshake", _root_sm->sm_id);
      //handle_http_server_open();
      _return_state = ServerTxnCreated;
      _root_sm->handleEvent(event, data);
    }
    return 0;
  }
  case VC_EVENT_READ_COMPLETE:
  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE:
    // Update the time out to the regular connection timeout.
    Debug("http_connect", "[%" PRId64 "] TCP Handshake complete", _root_sm->sm_id);
    _return_state = ServerTxnCreated;
    _root_sm->handleEvent(event, data);
    //server_entry->vc_handler = &HttpSM::state_send_server_request_header;

    // Reset the timeout to the non-connect timeout
    //server_txn->set_inactivity_timeout(get_server_inactivity_timeout());
    //handle_http_server_open();
    return 0;
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_ERROR:
  case NET_EVENT_OPEN_FAILED:
    s.current.state = HttpTransact::CONNECTION_ERROR;
    // save the errno from the connect fail for future use (passed as negative value, flip back)
    s.current.server->set_connect_fail(event == NET_EVENT_OPEN_FAILED ? -reinterpret_cast<intptr_t>(data) : ECONNABORTED);
    s.outbound_conn_track_state.clear();

    /* If we get this error in transparent mode, then we simply can't bind to the 4-tuple to make the connection.  There's no hope
       of retries succeeding in the near future. The best option is to just shut down the connection without further comment. The
       only known cause for this is outbound transparency combined with use client target address / source port, as noted in
       TS-1424. If the keep alives desync the current connection can be attempting to rebind the 4 tuple simultaneously with the
       shut down of an existing connection. Dropping the client side will cause it to pick a new source port and recover from this
       issue.
    */
    if (EADDRNOTAVAIL == s.current.server->connect_result && s.client_info.is_transparent) {
      if (is_debug_tag_set("http_tproxy")) {
        ip_port_text_buffer ip_c, ip_s;
        Debug("http_tproxy", "Force close of client connect (%s->%s) due to EADDRNOTAVAIL [%" PRId64 "]",
              ats_ip_nptop(&s.client_info.src_addr.sa, ip_c, sizeof ip_c),
              ats_ip_nptop(&s.server_info.dst_addr.sa, ip_s, sizeof ip_s), _root_sm->sm_id);
      }
      _return_state = ErrorTransparent;
      _root_sm->handleEvent(event, data);
      //s.client_info.keep_alive = HTTP_NO_KEEPALIVE; // part of the problem, clear it.
      //terminate_sm                   = true;
    } else if (ENET_THROTTLING == s.current.server->connect_result) {
      HTTP_INCREMENT_DYN_STAT(http_origin_connections_throttled_stat);
      //send_origin_throttled_response();
      _return_state = ErrorThrottle;
      _root_sm->handleEvent(event, data);
    } else {
      // Go ahead and release the failed server session.  Since it didn't receive a response, the release logic will
      // see that it didn't get a valid response and it will close it rather than returning it to the server session pool
      release_server_session();
      _return_state = ErrorResponse;
      _root_sm->handleEvent(event, data);
      //call_transact_and_set_next_state(HttpTransact::HandleResponse);
    }
    return 0;

  default:
    Error("[HttpSM::state_http_server_open] Unknown event: %d", event);
    ink_release_assert(0);
    return 0;
  }

  return 0;
}

