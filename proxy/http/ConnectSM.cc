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
#include "HttpTransactHeaders.h"
#include "Log.h"
#include "tscore/bwf_std_format.h"

using lbw = ts::LocalBufferWriter<256>;

inline static void
update_dns_info(HttpTransact::DNSLookupInfo *dns, HttpTransact::CurrentInfo *from, int attempts)
{
  dns->looking_up  = from->request_to;
  dns->lookup_name = from->server->name;
  dns->attempts    = attempts;
}

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
    res = static_cast<PoolableSession *>(_server_txn->get_proxy_ssn())->is_private();
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
ConnectSM::do_dns_lookup(HttpSM *sm)
{
  if (sm) {
    this->init(sm);
  }
  HttpTransact::State &s = _root_sm->t_state;
  sockaddr const *addr;

  if (s.api_server_addr_set) {
    /* If the API has set the server address before the OS DNS lookup
     * then we can skip the lookup
     */
    ip_text_buffer ipb;
    Debug("dns", "[HttpTransact::HandleRequest] Skipping DNS lookup for API supplied target %s.",
          ats_ip_ntop(&s.server_info.dst_addr, ipb, sizeof(ipb)));
    // this seems wasteful as we will just copy it right back
    ats_ip_copy(s.host_db_info.ip(), s.server_info.dst_addr);
    s.dns_info.lookup_success = true;
    this->_return_state       = ConnectSM::DnsHostdbSuccess;
    return ACTION_RESULT_DONE;
  } else if (0 == ats_ip_pton(s.dns_info.lookup_name, s.host_db_info.ip()) && ats_is_ip_loopback(s.host_db_info.ip())) {
    // If it's 127.0.0.1 or ::1 don't bother with hostdb
    Debug("dns", "[HttpTransact::HandleRequest] Skipping DNS lookup for %s because it's loopback", s.dns_info.lookup_name);
    s.dns_info.lookup_success = true;
    this->_return_state       = ConnectSM::DnsHostdbSuccess;
    return ACTION_RESULT_DONE;
  } else if (s.http_config_param->use_client_target_addr == 2 && !s.url_remap_success &&
             s.parent_result.result != PARENT_SPECIFIED && s.client_info.is_transparent &&
             s.dns_info.os_addr_style == HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_DEFAULT &&
             ats_is_ip(addr = _root_sm->ua_txn->get_netvc()->get_local_addr())) {
    /* If the connection is client side transparent and the URL
     * was not remapped/directed to parent proxy, we can use the
     * client destination IP address instead of doing a DNS
     * lookup. This is controlled by the 'use_client_target_addr'
     * configuration parameter.
     */
    if (is_debug_tag_set("dns")) {
      ip_text_buffer ipb;
      Debug("dns", "[HttpTransact::HandleRequest] Skipping DNS lookup for client supplied target %s.",
            ats_ip_ntop(addr, ipb, sizeof(ipb)));
    }
    ats_ip_copy(s.host_db_info.ip(), addr);
    if (s.hdr_info.client_request.version_get() == HTTPVersion(0, 9)) {
      s.host_db_info.app.http_data.http_version = HostDBApplicationInfo::HTTP_VERSION_09;
    } else if (s.hdr_info.client_request.version_get() == HTTPVersion(1, 0)) {
      s.host_db_info.app.http_data.http_version = HostDBApplicationInfo::HTTP_VERSION_10;
    } else {
      s.host_db_info.app.http_data.http_version = HostDBApplicationInfo::HTTP_VERSION_11;
    }

    s.dns_info.lookup_success = true;
    // cache this result so we don't have to unreliably duplicate the
    // logic later if the connect fails.
    s.dns_info.os_addr_style = HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_CLIENT;
    this->_return_state      = ConnectSM::DnsHostdbSuccess;
    return ACTION_RESULT_DONE;
  } else if (s.parent_result.result == PARENT_UNDEFINED && s.dns_info.lookup_success) {
    // Already set, and we don't have a parent proxy to lookup
    ink_assert(ats_is_ip(s.host_db_info.ip()));
    Debug("dns", "[HttpTransact::HandleRequest] Skipping DNS lookup, provided by plugin");
    this->_return_state = ConnectSM::DnsHostdbSuccess;
    return ACTION_RESULT_DONE;
  } else if (s.dns_info.looking_up == HttpTransact::ORIGIN_SERVER && s.http_config_param->no_dns_forward_to_parent &&
             s.parent_result.result != PARENT_UNDEFINED) {
    s.dns_info.lookup_success = true;
    this->_return_state       = ConnectSM::DnsHostdbSuccess;
    return ACTION_RESULT_DONE;
  }

  SET_HANDLER(&ConnectSM::state_hostdb_lookup);

  ink_assert(s.dns_info.looking_up != HttpTransact::UNDEFINED_LOOKUP);
  return do_hostdb_lookup();
}

Action *
ConnectSM::do_hostdb_lookup(HttpSM *sm)
{
  if (sm) {
    this->init(sm);
  }
  HttpTransact::State &s = _root_sm->t_state;
  ink_assert(s.dns_info.lookup_name != nullptr);
  ink_assert(_pending_action == nullptr);

  _root_sm->milestones[TS_MILESTONE_DNS_LOOKUP_BEGIN] = Thread::get_hrtime();

  if (s.txn_conf->srv_enabled) {
    char d[MAXDNAME];

    // Look at the next_hop_scheme to determine what scheme to put in the SRV lookup
    unsigned int scheme_len = sprintf(d, "_%s._tcp.", hdrtoken_index_to_wks(s.next_hop_scheme));
    ink_strlcpy(d + scheme_len, s.server_info.name, sizeof(d) - scheme_len);

    Debug("dns_srv", "Beginning lookup of SRV records for origin %s", d);

    HostDBProcessor::Options opt;
    if (s.api_txn_dns_timeout_value != -1) {
      opt.timeout = s.api_txn_dns_timeout_value;
    }
    Action *srv_lookup_action_handle =
      hostDBProcessor.getSRVbyname_imm(this, (cb_process_result_pfn)&ConnectSM::process_srv_info, d, 0, opt);

    if (srv_lookup_action_handle != ACTION_RESULT_DONE) {
      ink_assert(!_pending_action);
      _pending_action = srv_lookup_action_handle;
      return &_captive_action;
    } else {
      char *host_name = s.dns_info.srv_lookup_success ? s.dns_info.srv_hostname : s.dns_info.lookup_name;
      opt.port        = s.dns_info.srv_lookup_success ? s.dns_info.srv_port :
                                                 s.server_info.dst_addr.isValid() ? s.server_info.dst_addr.host_order_port() :
                                                                                    s.hdr_info.client_request.port_get();
      opt.flags = (s.cache_info.directives.does_client_permit_dns_storing) ? HostDBProcessor::HOSTDB_DO_NOT_FORCE_DNS :
                                                                             HostDBProcessor::HOSTDB_FORCE_DNS_RELOAD;
      opt.timeout = (s.api_txn_dns_timeout_value != -1) ? s.api_txn_dns_timeout_value : 0;
      opt.host_res_style =
        ats_host_res_from(_root_sm->ua_txn->get_netvc()->get_local_addr()->sa_family, s.txn_conf->host_res_data.order);

      Action *dns_lookup_action_handle =
        hostDBProcessor.getbyname_imm(this, (cb_process_result_pfn)&ConnectSM::process_hostdb_info, host_name, 0, opt);
      if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
        ink_assert(!_pending_action);
        _pending_action = dns_lookup_action_handle;
        return &_captive_action;
      } else {
        // call_transact_and_set_next_state(nullptr);
        this->_return_state = ConnectSM::DnsHostdbSuccess;
        return ACTION_RESULT_DONE;
      }
    }
  } else { /* we aren't using SRV stuff... */
    Debug("http_seq", "[HttpSM::do_hostdb_lookup] Doing DNS Lookup");

    // If there is not a current server, we must be looking up the origin
    //  server at the beginning of the transaction
    int server_port = 0;
    if (s.current.server && s.current.server->dst_addr.isValid()) {
      server_port = s.current.server->dst_addr.host_order_port();
    } else if (s.server_info.dst_addr.isValid()) {
      server_port = s.server_info.dst_addr.host_order_port();
    } else {
      server_port = s.hdr_info.client_request.port_get();
    }

    if (s.api_txn_dns_timeout_value != -1) {
      Debug("http_timeout", "beginning DNS lookup. allowing %d mseconds for DNS lookup", s.api_txn_dns_timeout_value);
    }

    HostDBProcessor::Options opt;
    opt.port  = server_port;
    opt.flags = (s.cache_info.directives.does_client_permit_dns_storing) ? HostDBProcessor::HOSTDB_DO_NOT_FORCE_DNS :
                                                                           HostDBProcessor::HOSTDB_FORCE_DNS_RELOAD;
    opt.timeout = (s.api_txn_dns_timeout_value != -1) ? s.api_txn_dns_timeout_value : 0;

    opt.host_res_style =
      ats_host_res_from(_root_sm->ua_txn->get_netvc()->get_local_addr()->sa_family, s.txn_conf->host_res_data.order);

    Action *dns_lookup_action_handle =
      hostDBProcessor.getbyname_imm(this, (cb_process_result_pfn)&ConnectSM::process_hostdb_info, s.dns_info.lookup_name, 0, opt);

    if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
      ink_assert(!_pending_action);
      _pending_action = dns_lookup_action_handle;
      return &_captive_action;
    } else {
      // call_transact_and_set_next_state(nullptr);
      this->_return_state = ConnectSM::DnsHostdbSuccess;
      return ACTION_RESULT_DONE;
    }
  }
}

Action *
ConnectSM::acquire_txn(HttpSM *sm, bool raw)
{
  if (sm) {
    this->init(sm);
  }
  HttpTransact::State &s = _root_sm->t_state;
  int ip_family          = s.current.server->dst_addr.sa.sa_family;
  auto fam_name          = ats_ip_family_name(ip_family);
  Debug("http_connect", "entered inside acquire_txn [%.*s]", static_cast<int>(fam_name.size()), fam_name.data());

  ink_release_assert(_pending_action == nullptr);

  this->_pending_action = nullptr;
  this->_sm_state       = WaitConnect;

  // Clean up connection tracking info if any. Need to do it now so the selected group
  // is consistent with the actual upstream in case of retry.
  s.outbound_conn_track_state.clear();

  ink_assert(s.current.server->dst_addr.port() != 0); // verify the plugin set it to something.

  char addrbuf[INET6_ADDRPORTSTRLEN];
  Debug("http_connect", "[%" PRId64 "] open connection to %s: %s", _root_sm->sm_id, s.current.server->name,
        ats_ip_nptop(&s.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)));

  if (_root_sm->plugin_tunnel) {
    PluginVCCore *t         = _root_sm->plugin_tunnel;
    _root_sm->plugin_tunnel = nullptr;
    SET_HANDLER(&ConnectSM::state_http_server_open);
    Action *pvc_action_handle = t->connect_re(this);

    // This connect call is always reentrant
    ink_release_assert(pvc_action_handle == ACTION_RESULT_DONE);
    this->_return_state = Tunnel;
    _root_sm->handleEvent(EVENT_DONE, nullptr);
    return pvc_action_handle;
  }

  Debug("http_connect", "[ConnectSM::acquire_txn] Sending request to server");

  _root_sm->milestones[TS_MILESTONE_SERVER_CONNECT] = Thread::get_hrtime();
  if (_root_sm->milestones[TS_MILESTONE_SERVER_FIRST_CONNECT] == 0) {
    _root_sm->milestones[TS_MILESTONE_SERVER_FIRST_CONNECT] = _root_sm->milestones[TS_MILESTONE_SERVER_CONNECT];
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
      _root_sm->handleEvent(EVENT_DONE, nullptr);
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

  if ((raw == false) && TS_SERVER_SESSION_SHARING_MATCH_NONE != s.txn_conf->server_session_sharing_match &&
      (s.txn_conf->keep_alive_post_out == 1 || s.hdr_info.request_content_length == 0) && !is_private() &&
      _root_sm->ua_txn != nullptr) {
    HSMresult_t shared_result;
    shared_result = httpSessionManager.acquire_session(this,                           // state machine
                                                       &s.current.server->dst_addr.sa, // ip + port
                                                       s.current.server->name,         // hostname
                                                       _root_sm->ua_txn);              // has ptr to bound ua sessions

    switch (shared_result) {
    case HSM_DONE:
      ink_release_assert(_server_txn != nullptr);
      _return_state = ServerTxnCreated;
      _root_sm->handleEvent(EVENT_DONE, nullptr);
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
           (_root_sm->ua_txn != nullptr)) {
    PoolableSession *existing_ss = _root_sm->ua_txn->get_server_session();

    if (existing_ss) {
      // [amc] Not sure if this is the best option, but we don't get here unless session sharing is disabled
      // so there's no point in further checking on the match or pool values. But why check anything? The
      // client has already exchanged a request with this specific origin server and has sent another one
      // shouldn't we just automatically keep the association?
      if (ats_ip_addr_port_eq(existing_ss->get_remote_addr(), &s.current.server->dst_addr.sa)) {
        _root_sm->ua_txn->attach_server_session(nullptr);
        existing_ss->set_active();
        _server_txn = existing_ss->new_transaction();
        ink_release_assert(_server_txn != nullptr);
        _return_state = ServerTxnCreated;
        _root_sm->handleEvent(EVENT_DONE, nullptr);
        return ACTION_RESULT_DONE;
      } else {
        // As this is in the non-sharing configuration, we want to close
        // the existing connection and call connect_re to get a new one
        existing_ss->set_inactivity_timeout(HRTIME_SECONDS(s.txn_conf->keep_alive_no_activity_timeout_out));
        existing_ss->release(_server_txn);
        _root_sm->ua_txn->attach_server_session(nullptr);
      }
    }
  }
  // Otherwise, we release the existing connection and call connect_re
  // to get a new one.
  // ua_txn is null when s.req_flavor == REQ_FLAVOR_SCHEDULED_UPDATE
  else if (_root_sm->ua_txn != nullptr) {
    PoolableSession *existing_ss = _root_sm->ua_txn->get_server_session();
    if (existing_ss) {
      existing_ss->set_inactivity_timeout(HRTIME_SECONDS(s.txn_conf->keep_alive_no_activity_timeout_out));
      existing_ss->release(_server_txn);
      _root_sm->ua_txn->attach_server_session(nullptr);
    }
  }

  // See if there is already a suitable connection started to the same origin

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
      s.current.state     = HttpTransact::CONNECTION_ERROR;
      this->_return_state = ErrorResponse;
      _root_sm->handleEvent(EVENT_DONE, nullptr);
      return ACTION_RESULT_DONE;
    }
  }

  // See if the outbound connection tracker data is needed. If so, get it here for consistency.
  if (s.txn_conf->outbound_conntrack.max > 0 || s.txn_conf->outbound_conntrack.min > 0) {
    s.outbound_conn_track_state = OutboundConnTrack::obtain(s.txn_conf->outbound_conntrack,
                                                            std::string_view{s.current.server->name}, s.current.server->dst_addr);
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
          using lbw = ts::LocalBufferWriter<256>;
          ct_state.rescheduled();
          Debug("http_connect", "%s", lbw().print("[{}] queued for {}\0", _root_sm->sm_id, s.current.server->dst_addr).data());
          _pending_action =
            eventProcessor.schedule_in(this, HRTIME_MSECONDS(s.http_config_param->outbound_conntrack.queue_delay.count()));
        } else {              // the queue is full
          ct_state.dequeue(); // release the queue slot
          ct_state.blocked(); // note the blockage.
        }
      } else { // queue size is 0, always block.
        ct_state.blocked();
      }

      ct_state.Warn_Blocked(&s.txn_conf->outbound_conntrack, _root_sm->sm_id, ccount - 1, &s.current.server->dst_addr.sa,
                            is_debug_tag_set("http") ? "http" : nullptr);

      if (_pending_action) {
        return &_captive_action;
      } else {
        _return_state = ErrorThrottle;
        _root_sm->handleEvent(EVENT_DONE, nullptr);
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
  opt.set_sock_param(s.txn_conf->sock_recv_buffer_size_out, s.txn_conf->sock_send_buffer_size_out, s.txn_conf->sock_option_flag_out,
                     s.txn_conf->sock_packet_mark_out, s.txn_conf->sock_packet_tos_out);

  set_tls_options(opt, s.txn_conf);

  opt.ip_family = ip_family;

  int scheme_to_use = s.scheme; // get initial scheme
  bool tls_upstream = scheme_to_use == URL_WKSIDX_HTTPS;
  if (_root_sm->ua_txn) {
    if (raw) {
      SSLNetVConnection *ssl_vc = dynamic_cast<SSLNetVConnection *>(_root_sm->ua_txn->get_netvc());
      if (ssl_vc) {
        tls_upstream = ssl_vc->upstream_tls();
      }
    }
    opt.local_port = _root_sm->ua_txn->get_outbound_port();

    const IpAddr &outbound_ip =
      AF_INET6 == opt.ip_family ? _root_sm->ua_txn->get_outbound_ip6() : _root_sm->ua_txn->get_outbound_ip4();
    if (outbound_ip.isValid()) {
      opt.addr_binding = NetVCOptions::INTF_ADDR;
      opt.local_ip     = outbound_ip;
    } else if (_root_sm->ua_txn->is_outbound_transparent()) {
      opt.addr_binding = NetVCOptions::FOREIGN_ADDR;
      opt.local_ip     = s.client_info.src_addr;
      /* If the connection is server side transparent, we can bind to the
         port that the client chose instead of randomly assigning one at
         the proxy.  This is controlled by the 'use_client_source_port'
         configuration parameter.
      */

      NetVConnection *client_vc = _root_sm->ua_txn->get_netvc();
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

    std::string_view sni_name = _root_sm->get_outbound_sni();
    if (sni_name.length() > 0) {
      opt.set_sni_servername(sni_name.data(), sni_name.length());
    }
    int len = 0;
    if (s.txn_conf->ssl_client_sni_policy != nullptr && !strcmp(s.txn_conf->ssl_client_sni_policy, "verify_with_name_source")) {
      // also set sni_hostname with host header from server request in this policy
      const char *host = s.hdr_info.server_request.host_get(&len);
      if (host && len > 0) {
        opt.set_sni_hostname(host, len);
      }
    }
    if (s.server_info.name) {
      opt.set_ssl_servername(s.server_info.name);
    }

    connect_action_handle = sslNetProcessor.connect_re(this,                           // state machine
                                                       &s.current.server->dst_addr.sa, // addr + port
                                                       &opt);
  } else {
    Debug("http_connect", "calling netProcessor.connect_re");
    connect_action_handle = netProcessor.connect_re(this,                           // state machine
                                                    &s.current.server->dst_addr.sa, // addr + port
                                                    &opt);
  }

  if (connect_action_handle != ACTION_RESULT_DONE) {
    ink_assert(!_pending_action);
    _pending_action = connect_action_handle;
    return &_captive_action;
  } else {
    return &_captive_action;
  }
}

int
ConnectSM::state_http_server_raw_open(int event, void *data)
{
  _root_sm->milestones[TS_MILESTONE_SERVER_CONNECT_END] = Thread::get_hrtime();

  ink_release_assert(_sm_state == WaitConnect || _sm_state == RetryConnect);

  _pending_action = nullptr;
  switch (event) {
  case NET_EVENT_OPEN:
    _netvc        = static_cast<NetVConnection *>(data);
    _return_state = ServerTxnCreated;
    _root_sm->handleEvent(event, data);

    break;

  case VC_EVENT_ERROR:
  case NET_EVENT_OPEN_FAILED:
    _return_state = ErrorTransparent;
    _root_sm->handleEvent(event, data);
    break;

  default:
    ink_release_assert(0);
    break;
  }

  // call_transact_and_set_next_state(HttpTransact::OriginServerRawOpen);
  return 0;
}

void
ConnectSM::create_server_txn()
{
  HttpTransact::State &s      = _root_sm->t_state;
  Http1ServerSession *session = (TS_SERVER_SESSION_SHARING_POOL_THREAD == s.http_config_param->server_session_sharing_pool) ?
                                  THREAD_ALLOC_INIT(httpServerSessionAllocator, mutex->thread_holding) :
                                  httpServerSessionAllocator.alloc();
  session->sharing_pool  = static_cast<TSServerSessionSharingPoolType>(s.http_config_param->server_session_sharing_pool);
  session->sharing_match = static_cast<TSServerSessionSharingMatchMask>(s.txn_conf->server_session_sharing_match);

  session->attach_hostname(s.current.server->name);

  session->new_connection(_netvc, _netvc_read_buffer, _netvc_reader);

  ATS_PROBE1(new_origin_server_connection, s.current.server->name);

  session->set_active();
  ats_ip_copy(&s.server_info.src_addr, _netvc->get_local_addr());

  // If origin_max_connections or origin_min_keep_alive_connections is set then we are metering
  // the max and or min number of connections per host. Transfer responsibility for this to the
  // session object.
  if (s.outbound_conn_track_state.is_active()) {
    Debug("http_connect", "[%" PRId64 "] max number of outbound connections: %d", _root_sm->sm_id,
          s.txn_conf->outbound_conntrack.max);
    session->enable_outbound_connection_tracking(s.outbound_conn_track_state.drop());
  }
  _server_txn = session->new_transaction();
  if (s.current.request_to == HttpTransact::PARENT_PROXY) {
    session->to_parent_proxy = true;
    HTTP_INCREMENT_DYN_STAT(http_current_parent_proxy_connections_stat);
    HTTP_INCREMENT_DYN_STAT(http_total_parent_proxy_connections_stat);
  } else {
    session->to_parent_proxy = false;
  }
  //_server_txn->do_io_write(this, 1, _server_txn->get_reader());
  _netvc             = nullptr;
  _netvc_read_buffer = nullptr;
  _netvc_reader      = nullptr;
}

int
ConnectSM::state_http_server_open(int event, void *data)
{
  HttpTransact::State &s = _root_sm->t_state;
  Debug("http_connect", "entered inside state_http_server_open");
  ink_release_assert(_sm_state == WaitConnect || _sm_state == RetryConnect);
  if (event != NET_EVENT_OPEN) {
    _pending_action = nullptr;
  }
  _root_sm->milestones[TS_MILESTONE_SERVER_CONNECT_END] = Thread::get_hrtime();

  switch (event) {
  case NET_EVENT_OPEN: {
    // Since the UnixNetVConnection::action_ or SocksEntry::action_ may be returned from netProcessor.connect_re, and the
    // SocksEntry::action_ will be copied into UnixNetVConnection::action_ before call back NET_EVENT_OPEN from SocksEntry::free(),
    // so we just compare the Continuation between pending_action and VC's action_.
    _netvc                 = static_cast<NetVConnection *>(data);
    UnixNetVConnection *vc = static_cast<UnixNetVConnection *>(_netvc);
    ink_release_assert(_pending_action == nullptr || _pending_action->continuation == vc->get_action()->continuation);
    _pending_action = nullptr;
    if (_root_sm->plugin_tunnel_type == HTTP_NO_PLUGIN_TUNNEL) {
      Debug("http_connect", "[%" PRId64 "] setting handler for TCP handshake", _root_sm->sm_id);
      // Just want to get a write-ready event so we know that the TCP handshake is complete.
      //_server_txn->handler = (ContinuationHandler)&ConnectSM::state_http_server_open;
      //_netvc->do_io_write(this, 1, _server_txn->get_reader());
      _netvc_read_buffer = new_MIOBuffer(HTTP_SERVER_RESP_HDR_BUFFER_INDEX);
      _netvc_reader      = _netvc_read_buffer->alloc_reader();
      _netvc->do_io_write(this, 1, _netvc_reader);
    } else { // in the case of an intercept plugin don't to the connect timeout change
      Debug("http_connect", "[%" PRId64 "] not setting handler for TCP handshake", _root_sm->sm_id);
      this->create_server_txn();
      _return_state = ServerTxnCreated;
      _root_sm->handleEvent(event, data);
    }
    ink_release_assert(_pending_action == nullptr);
    return 0;
  }
  case VC_EVENT_READ_COMPLETE:
  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE:
    // Update the time out to the regular connection timeout.
    Debug("http_connect", "[%" PRId64 "] TCP Handshake complete", _root_sm->sm_id);
    _netvc->do_io_write(nullptr, 0, nullptr);
    this->create_server_txn();
    _return_state = ServerTxnCreated;
    _root_sm->handleEvent(event, data);
    ink_release_assert(_pending_action == nullptr);
    return 0;
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_ERROR:
  case NET_EVENT_OPEN_FAILED:
    _netvc->do_io_write(nullptr, 0, nullptr);
    this->_sm_state = FailConnect;
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
    } else if (ENET_THROTTLING == s.current.server->connect_result) {
      HTTP_INCREMENT_DYN_STAT(http_origin_connections_throttled_stat);
      _return_state = ErrorThrottle;
      _root_sm->handleEvent(event, data);
    } else {
      // See if we should retry the request
      if (!this->do_retry_request()) {
        // Go ahead and release the failed server session.  Since it didn't receive a response, the release logic will
        // see that it didn't get a valid response and it will close it rather than returning it to the server session pool
        _return_state = ErrorResponse;
        _root_sm->handleEvent(event, data);
      }
    }
    return 0;

  default:
    Error("[HttpSM::state_http_server_open] Unknown event: %d", event);
    ink_release_assert(0);
    return 0;
  }

  return 0;
}

Action *
ConnectSM::retry_connection(HttpSM *sm)
{
  ink_release_assert(_pending_action == nullptr);
  this->init(sm);
  this->_sm_state = FailConnect;
  if (do_retry_request()) {
    return &_captive_action;
  }
  return ACTION_RESULT_DONE; // Connection already done
}

bool
ConnectSM::do_retry_request()
{
  HttpTransact::State &s = _root_sm->t_state;
  // Only doing the server path first
  if (s.current.request_to == HttpTransact::ORIGIN_SERVER) {
    unsigned max_connect_retries = 0;

    s.server_info.state = s.current.state;

    switch (s.current.state) {
    case HttpTransact::CONNECTION_ALIVE:
    case HttpTransact::OUTBOUND_CONGESTION:
    case HttpTransact::ACTIVE_TIMEOUT:
      // No need to retry, just go away
      return false;
    case HttpTransact::OPEN_RAW_ERROR:
    /* fall through */
    case HttpTransact::CONNECTION_ERROR:
    /* fall through */
    case HttpTransact::STATE_UNDEFINED:
    /* fall through */
    case HttpTransact::INACTIVE_TIMEOUT:
    /* fall through */
    case HttpTransact::PARSE_ERROR:
    /* fall through */
    case HttpTransact::CONNECTION_CLOSED:
    /* fall through */
    case HttpTransact::BAD_INCOMING_RESPONSE:

      // Set to generic I/O error if not already set specifically.
      if (!s.current.server->had_connect_fail()) {
        s.current.server->set_connect_fail(EIO);
      }
      if (HttpTransact::is_server_negative_cached(&s)) {
        max_connect_retries = s.txn_conf->connect_attempts_max_retries_dead_server;
      } else {
        // server not yet negative cached - use default number of retries
        max_connect_retries = s.txn_conf->connect_attempts_max_retries;
      }

      // Set up the retry
      if (HttpTransact::is_request_retryable(&s) && s.current.attempts < max_connect_retries) {
        _root_sm->reset_server();
        _server_txn = nullptr;
        // If this is a round robin DNS entry & we're tried configured
        //    number of times, we should try another node
        if (HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_CLIENT == s.dns_info.os_addr_style) {
          // attempt was based on client supplied server address. Try again
          // using HostDB.
          // Allow DNS attempt
          s.dns_info.lookup_success = false;
          // See if we can get data from HostDB for this.
          s.dns_info.os_addr_style = HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_HOSTDB;
          // Force host resolution to have the same family as the client.
          // Because this is a transparent connection, we can't switch address
          // families - that is locked in by the client source address.
          ats_force_order_by_family(&s.current.server->dst_addr.sa, s.my_txn_conf().host_res_data.order);

          // Invoke DNS.  Set state to Connect next
          Action *action_handle = this->do_dns_lookup();
          _sm_state             = RetryAddress;
          if (action_handle != ACTION_RESULT_DONE) {
            _pending_action = action_handle;
          } else {
            // Invoke Connect logic
            Action *action_handle = this->acquire_txn();
            _sm_state             = RetryConnect;
            if (action_handle != ACTION_RESULT_DONE) {
              _pending_action = action_handle;
            } else {
            }
          }
        } else if ((s.dns_info.srv_lookup_success || s.host_db_info.is_rr_elt()) && (s.txn_conf->connect_attempts_rr_retries > 0) &&
                   ((s.current.attempts + 1) % s.txn_conf->connect_attempts_rr_retries == 0)) {
          // SKH - Does this case retry?
          this->delete_server_rr_entry(max_connect_retries);
          SET_HANDLER(&ConnectSM::state_mark_os_down);
          do_hostdb_update_if_necessary();
          _sm_state             = RetryAddress;
          Action *action_handle = this->do_dns_lookup();
          if (action_handle != ACTION_RESULT_DONE) {
            _pending_action = action_handle;
          } else {
            _sm_state = RetryConnect;
            ReDNSRoundRobin();
            // Invoke Connect logic
            Action *action_handle = this->acquire_txn();
            if (action_handle != ACTION_RESULT_DONE) {
              _pending_action = action_handle;
            } else {
            }
          }
          // Invoke DNS.  Set state to Connect next
          return true;
        } else {
          HttpTransact::retry_server_connection_not_open(&s, s.current.state, max_connect_retries);
          Debug("http_trans", "[handle_response_from_server] Error. Retrying...");
          s.next_action = HttpTransact::how_to_open_connection(&s);

          if (s.api_server_addr_set) {
            // If the plugin set a server address, back up to the OS_DNS hook
            // to let it try another one. Force OS_ADDR_USE_CLIENT so that
            // in OSDNSLoopkup, we back up to how_to_open_connections which
            // will tell HttpSM to connect the origin server.

            s.dns_info.os_addr_style = HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_USE_CLIENT;
            // TRANSACT_RETURN(SM_ACTION_API_OS_DNS, OSDNSLookup);
            // Invoke DNS.  Set state to Connect next
            _sm_state             = RetryAddress;
            Action *action_handle = this->do_dns_lookup();
            if (action_handle != ACTION_RESULT_DONE) {
              _pending_action = action_handle;
            } else {
              // Invoke Connect logic
              _sm_state             = RetryConnect;
              Action *action_handle = this->acquire_txn();
              if (action_handle != ACTION_RESULT_DONE) {
                _pending_action = action_handle;
              }
            }
            // Invoke DNS.  Set state to Connect next
          } else {
            // Invoke Connect logic
            _sm_state             = RetryConnect;
            Action *action_handle = this->acquire_txn();
            if (action_handle != ACTION_RESULT_DONE) {
              _pending_action = action_handle;
            }
          }
        }
        return true;
      } else {
        return false; // Cannot retry, go away
      }
      break;
    default:
      ink_assert(!("s->current.state is set to something unsupported"));
      break;
    }
  }
  return false;
}

int
ConnectSM::state_hostdb_lookup(int event, void *data)
{
  HttpTransact::State &s = _root_sm->t_state;
  //    ink_assert (m_origin_server_vc == 0);
  // REQ_FLAVOR_SCHEDULED_UPDATE can be transformed into
  // REQ_FLAVOR_REVPROXY
  // ink_assert(s.req_flavor == HttpTransact::REQ_FLAVOR_SCHEDULED_UPDATE || s.req_flavor == HttpTransact::REQ_FLAVOR_REVPROXY);

  switch (event) {
  case EVENT_HOST_DB_LOOKUP:
    _pending_action = nullptr;
    process_hostdb_info(static_cast<HostDBInfo *>(data));
    // Call handler on SM
    // call_transact_and_set_next_state(nullptr);
    if (_sm_state == RetryAddress) {
      // Move onto the connect State
      _sm_state = RetryConnect;
      this->acquire_txn();
    } else { // Termimal
      _return_state = DnsHostdbSuccess;
      _root_sm->handleEvent(event, &_captive_action);
    }
    break;
  case EVENT_SRV_LOOKUP: {
    _pending_action = nullptr;
    process_srv_info(static_cast<HostDBInfo *>(data));

    char *host_name = s.dns_info.srv_lookup_success ? s.dns_info.srv_hostname : s.dns_info.lookup_name;
    HostDBProcessor::Options opt;
    opt.port  = s.dns_info.srv_lookup_success ? s.dns_info.srv_port : s.server_info.dst_addr.host_order_port();
    opt.flags = (s.cache_info.directives.does_client_permit_dns_storing) ? HostDBProcessor::HOSTDB_DO_NOT_FORCE_DNS :
                                                                           HostDBProcessor::HOSTDB_FORCE_DNS_RELOAD;
    opt.timeout = (s.api_txn_dns_timeout_value != -1) ? s.api_txn_dns_timeout_value : 0;
    opt.host_res_style =
      ats_host_res_from(_root_sm->ua_txn->get_netvc()->get_local_addr()->sa_family, s.txn_conf->host_res_data.order);

    Action *dns_lookup_action_handle =
      hostDBProcessor.getbyname_imm(this, (cb_process_result_pfn)&ConnectSM::process_hostdb_info, host_name, 0, opt);
    if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
      ink_assert(!_pending_action);
      _pending_action = dns_lookup_action_handle;
    } else {
      if (_sm_state == RetryAddress) {
        _sm_state = RetryConnect;
        this->acquire_txn();
      } else {
        _return_state = DnsHostdbSuccess;
        _root_sm->handleEvent(event, &_captive_action);
      }
      // call_transact_and_set_next_state(nullptr);
    }
  } break;
  case EVENT_HOST_DB_IP_REMOVED:
    ink_assert(!"Unexpected event from HostDB");
    break;
  default:
    ink_assert(!"Unexpected event");
  }

  return 0;
}

void
ConnectSM::init(HttpSM *sm)
{
  this->_root_sm        = sm;
  this->mutex           = sm->mutex;
  this->_server_txn     = nullptr;
  this->_netvc          = nullptr;
  this->_sm_state       = UndefinedSMState;
  this->_pending_action = nullptr;
}

void
ConnectSM::cleanup()
{
  if (_netvc) {
    _netvc->do_io_close();
    _netvc = nullptr;
  }
  if (_netvc_read_buffer) {
    free_MIOBuffer(_netvc_read_buffer);
    _netvc_read_buffer = nullptr;
    _netvc_reader      = nullptr;
  }
  if (_server_txn) {
    _server_txn->do_io_close();
    _server_txn = nullptr;
  }
}

void
ConnectSM::process_srv_info(HostDBInfo *r)
{
  HttpTransact::State &s = _root_sm->t_state;
  Debug("dns_srv", "beginning process_srv_info");
  s.hostdb_entry = Ptr<HostDBInfo>(r);

  /* we didn't get any SRV records, continue w normal lookup */
  if (!r || !r->is_srv || !r->round_robin) {
    s.dns_info.srv_hostname[0]    = '\0';
    s.dns_info.srv_lookup_success = false;
    s.my_txn_conf().srv_enabled   = false;
    Debug("dns_srv", "No SRV records were available, continuing to lookup %s", s.dns_info.lookup_name);
  } else {
    HostDBRoundRobin *rr = r->rr();
    HostDBInfo *srv      = nullptr;
    if (rr) {
      srv = rr->select_best_srv(s.dns_info.srv_hostname, &mutex->thread_holding->generator, ink_local_time(),
                                static_cast<int>(s.txn_conf->down_server_timeout));
    }
    if (!srv) {
      s.dns_info.srv_lookup_success = false;
      s.dns_info.srv_hostname[0]    = '\0';
      s.my_txn_conf().srv_enabled   = false;
      Debug("dns_srv", "SRV records empty for %s", s.dns_info.lookup_name);
    } else {
      s.dns_info.srv_lookup_success = true;
      s.dns_info.srv_port           = srv->data.srv.srv_port;
      s.dns_info.srv_app            = srv->app;
      ink_assert(srv->data.srv.key == makeHostHash(s.dns_info.srv_hostname));
      Debug("dns_srv", "select SRV records %s", s.dns_info.srv_hostname);
    }
  }
  return;
}

void
ConnectSM::process_hostdb_info(HostDBInfo *r)
{
  HttpTransact::State &s = _root_sm->t_state;
  // Increment the refcount to our item, since we are pointing at it
  s.hostdb_entry = Ptr<HostDBInfo>(r);

  sockaddr const *client_addr = nullptr;
  bool use_client_addr        = s.http_config_param->use_client_target_addr == 1 && s.client_info.is_transparent &&
                         s.dns_info.os_addr_style == HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_DEFAULT;
  if (use_client_addr) {
    NetVConnection *vc = _root_sm->ua_txn ? _root_sm->ua_txn->get_netvc() : nullptr;
    if (vc) {
      client_addr = vc->get_local_addr();
      // Regardless of whether the client address matches the DNS record or not,
      // we want to use that address.  Therefore, we copy over the client address
      // info and skip the assignment from the DNS cache
      ats_ip_copy(s.host_db_info.ip(), client_addr);
      s.dns_info.os_addr_style  = HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_CLIENT;
      s.dns_info.lookup_success = true;
      // Leave ret unassigned, so we don't overwrite the host_db_info
    } else {
      use_client_addr = false;
    }
  }

  if (r && !r->is_failed()) {
    ink_time_t now              = ink_local_time();
    HostDBInfo *ret             = nullptr;
    s.dns_info.lookup_success   = true;
    s.dns_info.lookup_validated = true;

    HostDBRoundRobin *rr = r->round_robin ? r->rr() : nullptr;
    if (rr) {
      // if use_client_target_addr is set, make sure the client addr is in the results pool
      if (use_client_addr && rr->find_ip(client_addr) == nullptr) {
        Debug("http", "use_client_target_addr == 1. Client specified address is not in the pool, not validated.");
        s.dns_info.lookup_validated = false;
      } else {
        // Since the time elapsed between current time and client_request_time
        // may be very large, we cannot use client_request_time to approximate
        // current time when calling select_best_http().
        ret = rr->select_best_http(&s.client_info.src_addr.sa, now, static_cast<int>(s.txn_conf->down_server_timeout));
        // set the srv target`s last_failure
        if (s.dns_info.srv_lookup_success) {
          uint32_t last_failure = 0xFFFFFFFF;
          for (int i = 0; i < rr->rrcount && last_failure != 0; ++i) {
            if (last_failure > rr->info(i).app.http_data.last_failure) {
              last_failure = rr->info(i).app.http_data.last_failure;
            }
          }

          if (last_failure != 0 && static_cast<uint32_t>(now - s.txn_conf->down_server_timeout) < last_failure) {
            HostDBApplicationInfo app;
            app.allotment.application1 = 0;
            app.allotment.application2 = 0;
            app.http_data.last_failure = last_failure;
            hostDBProcessor.setby_srv(s.dns_info.lookup_name, 0, s.dns_info.srv_hostname, &app);
          }
        }
      }
    } else {
      if (use_client_addr && !ats_ip_addr_eq(client_addr, &r->data.ip.sa)) {
        Debug("http", "use_client_target_addr == 1. Comparing single addresses failed, not validated.");
        s.dns_info.lookup_validated = false;
      } else {
        ret = r;
      }
    }
    if (ret) {
      s.host_db_info = *ret;
      ink_release_assert(!s.host_db_info.reverse_dns);
      ink_release_assert(ats_is_ip(s.host_db_info.ip()));
    }
  } else {
    Debug("http", "[%" PRId64 "] DNS lookup failed for '%s'", _root_sm->sm_id, s.dns_info.lookup_name);

    if (!use_client_addr) {
      s.dns_info.lookup_success = false;
    }
    s.host_db_info.app.allotment.application1 = 0;
    s.host_db_info.app.allotment.application2 = 0;
    ink_assert(!s.host_db_info.round_robin);
  }

  _root_sm->milestones[TS_MILESTONE_DNS_LOOKUP_END] = Thread::get_hrtime();

  if (is_debug_tag_set("http_timeout")) {
    if (s.api_txn_dns_timeout_value != -1) {
      int foo = static_cast<int>(_root_sm->milestones.difference_msec(TS_MILESTONE_DNS_LOOKUP_BEGIN, TS_MILESTONE_DNS_LOOKUP_END));
      Debug("http_timeout", "DNS took: %d msec", foo);
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// Name       : delete_server_rr_entry
// Description:
//
// Details    :
//
//   connection to server failed mark down the server round robin entry
//
//
// Possible Next States From Here:
//
///////////////////////////////////////////////////////////////////////////////
void
ConnectSM::delete_server_rr_entry(int max_retries)
{
  HttpTransact::State &s = _root_sm->t_state;
  char addrbuf[INET6_ADDRSTRLEN];

  Debug("http_trans", "[%d] failed to connect to %s", s.current.attempts,
        ats_ip_ntop(&s.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)));
  Debug("http_trans", "[delete_server_rr_entry] marking rr entry down and finding next one");
  ink_assert(s.current.server->had_connect_fail());
  ink_assert(s.current.request_to == HttpTransact::ORIGIN_SERVER);
  ink_assert(s.current.server == &s.server_info);
  update_dns_info(&s.dns_info, &s.current, 0);
  s.current.attempts++;
  Debug("http_trans", "[delete_server_rr_entry] attempts now: %d, max: %d", s.current.attempts, max_retries);
  // TRANSACT_RETURN(SM_ACTION_ORIGIN_SERVER_RR_MARK_DOWN, ReDNSRoundRobin);
}

void
ConnectSM::do_hostdb_update_if_necessary()
{
  HttpTransact::State &s = _root_sm->t_state;
  int issue_update       = 0;

  if (s.current.server == nullptr || _root_sm->plugin_tunnel_type != HTTP_NO_PLUGIN_TUNNEL) {
    // No server, so update is not necessary
    return;
  }
  // If we failed back over to the origin server, we don't have our
  //   hostdb information anymore which means we shouldn't update the hostdb
  if (!ats_ip_addr_eq(&s.current.server->dst_addr.sa, s.host_db_info.ip())) {
    Debug("http", "[%" PRId64 "] skipping hostdb update due to server failover", _root_sm->sm_id);
    return;
  }

  if (s.updated_server_version != HostDBApplicationInfo::HTTP_VERSION_UNDEFINED) {
    // we may have incorrectly assumed that the hostdb had the wrong version of
    // http for the server because our first few connect attempts to the server
    // failed, causing us to downgrade our requests to a lower version and changing
    // our information about the server version.
    //
    // This test therefore just issues the update only if the hostdb version is
    // in fact different from the version we want the value to be updated to.
    if (s.host_db_info.app.http_data.http_version != s.updated_server_version) {
      s.host_db_info.app.http_data.http_version = s.updated_server_version;
      issue_update |= 1;
    }

    s.updated_server_version = HostDBApplicationInfo::HTTP_VERSION_UNDEFINED;
  }
  // Check to see if we need to report or clear a connection failure
  if (s.current.server->had_connect_fail()) {
    issue_update |= 1;
    mark_host_failure(&s.host_db_info, s.client_request_time);
  } else {
    if (s.host_db_info.app.http_data.last_failure != 0) {
      s.host_db_info.app.http_data.last_failure = 0;
      issue_update |= 1;
      char addrbuf[INET6_ADDRPORTSTRLEN];
      Debug("http", "[%" PRId64 "] hostdb update marking IP: %s as up", _root_sm->sm_id,
            ats_ip_nptop(&s.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)));
    }

    if (s.dns_info.srv_lookup_success && s.dns_info.srv_app.http_data.last_failure != 0) {
      s.dns_info.srv_app.http_data.last_failure = 0;
      hostDBProcessor.setby_srv(s.dns_info.lookup_name, 0, s.dns_info.srv_hostname, &s.dns_info.srv_app);
      Debug("http", "[%" PRId64 "] hostdb update marking SRV: %s as up", _root_sm->sm_id, s.dns_info.srv_hostname);
    }
  }

  if (issue_update) {
    hostDBProcessor.setby(s.current.server->name, strlen(s.current.server->name), &s.current.server->dst_addr.sa,
                          &s.host_db_info.app);
  }

  char addrbuf[INET6_ADDRPORTSTRLEN];
  Debug("http", "server info = %s", ats_ip_nptop(&s.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)));
  return;
}

void
ConnectSM::mark_host_failure(HostDBInfo *info, time_t time_down)
{
  HttpTransact::State &s = _root_sm->t_state;
  char addrbuf[INET6_ADDRPORTSTRLEN];

  if (info->app.http_data.last_failure == 0) {
    char *url_str = s.hdr_info.client_request.url_string_get(&s.arena, nullptr);
    Log::error("%s", lbw()
                       .clip(1)
                       .print("CONNECT Error: {} connecting to {} for '{}' (setting last failure time)",
                              ts::bwf::Errno(s.current.server->connect_result), s.current.server->dst_addr,
                              ts::bwf::FirstOf(url_str, "<none>"))
                       .extend(1)
                       .write('\0')
                       .data());

    if (url_str) {
      s.arena.str_free(url_str);
    }
  }

  info->app.http_data.last_failure = time_down;

#ifdef DEBUG
  ink_assert(ink_local_time() + s.txn_conf->down_server_timeout > time_down);
#endif

  Debug("http", "[%" PRId64 "] hostdb update marking IP: %s as down", _root_sm->sm_id,
        ats_ip_nptop(&s.current.server->dst_addr.sa, addrbuf, sizeof(addrbuf)));
}

int
ConnectSM::state_mark_os_down(int event, void *data)
{
  HostDBInfo *mark_down  = nullptr;
  HttpTransact::State &s = _root_sm->t_state;

  if (event == EVENT_HOST_DB_LOOKUP && data) {
    HostDBInfo *r = static_cast<HostDBInfo *>(data);

    if (r->round_robin) {
      // Look for the entry we need mark down in the round robin
      ink_assert(s.current.server != nullptr);
      ink_assert(s.current.request_to == HttpTransact::ORIGIN_SERVER);
      if (s.current.server) {
        mark_down = r->rr()->find_ip(&s.current.server->dst_addr.sa);
      }
    } else {
      // No longer a round robin, check to see if our address is the same
      if (ats_ip_addr_eq(s.host_db_info.ip(), r->ip())) {
        mark_down = r;
      }
    }

    if (mark_down) {
      mark_host_failure(mark_down, s.request_sent_time);
    }
  }
  // We either found our entry or we did not.  Either way find
  //  the entry we should use now
  return state_hostdb_lookup(event, data);
}

bool
ConnectSM::ReDNSRoundRobin()
{
  HttpTransact::State &s = _root_sm->t_state;
  ink_assert(s.current.server == &s.server_info);
  ink_assert(s.current.server->had_connect_fail());

  if (s.dns_info.lookup_success) {
    // We using a new server now so clear the connection
    //  failure mark
    s.current.server->clear_connect_fail();

    // Our ReDNS of the server succeeded so update the necessary
    //  information and try again. Need to preserve the current port value if possible.
    in_port_t server_port = s.current.server->dst_addr.host_order_port();
    // Temporary check to make sure the port preservation can be depended upon. That should be the case
    // because we get here only after trying a connection. Remove for 6.2.
    ink_assert(s.current.server->dst_addr.isValid() && 0 != server_port);

    ats_ip_copy(&s.server_info.dst_addr, s.host_db_info.ip());
    s.server_info.dst_addr.port() = htons(server_port);
    ats_ip_copy(&s.request_data.dest_ip, &s.server_info.dst_addr);
    HttpTransact::get_ka_info_from_host_db(&s, &s.server_info, &s.client_info, &s.host_db_info);

    char addrbuf[INET6_ADDRSTRLEN];
    Debug("http_trans", "[ReDNSRoundRobin] DNS lookup for O.S. successful IP: %s",
          ats_ip_ntop(&s.server_info.dst_addr.sa, addrbuf, sizeof(addrbuf)));
    return true;
  } else {
    // Our ReDNS failed so output the DNS failure error message
    _return_state = ErrorDNS;
    return false;
  }
}
