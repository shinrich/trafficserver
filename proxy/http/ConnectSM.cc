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

#define CONNECT_SM_SET_DEFAULT_HANDLER(_h)   \
  {                                       \
    default_handler = _h;                 \
  }

#define STATE_ENTER(e, r)                             \
  {                                                \
    _root_sm->history.push_back(MakeSourceLocation(), e, r); \
  }

void
ConnectSM::call_transact_and_transition(ReturnFunc f)
{
  ConnectSM::Action last_action;
  // The callee can either specify a method to call in to Transact,
  //   or call with NULL which indicates that Transact should use
  //   its stored entry point.
  if (f == nullptr) {
    ink_release_assert(_return_point != nullptr);
    _return_point();
  } else {
    f();
  }

  Debug("http", "[%" PRId64 "] State Transition: %d -> %d", _root_sm->sm_id, last_action, _next_action);

  transition_state();
}

/*
 * Perform the actions needed to transition from _state to _next_state
 */
void 
ConnectSM::transition_state()
{
  HttpTransact::State &state = _root_sm->t_state;

  switch (_next_action) {
  case ConnectSM::Done: 
    // Go back to outer SM
    _root_sm->call_transact_and_set_next_state(nullptr);
    break;
  case ConnectSM::DnsRequest: {
    sockaddr const *addr;

    if (state.api_server_addr_set) {
      /* If the API has set the server address before the OS DNS lookup
       * then we can skip the lookup
       */
      ip_text_buffer ipb;
      Debug("dns", "Skipping DNS lookup for API supplied target %s.",
              ats_ip_ntop(&state.server_info.dst_addr, ipb, sizeof(ipb)));
      // this seems wasteful as we will just copy it right back
      ats_ip_copy(state.host_db_info.ip(), &state.server_info.dst_addr);
      state.dns_info.lookup_success = true;

      // Go back...
      //call_transact_and_set_next_state(nullptr);
      break;
    } else if (0 == ats_ip_pton(state.dns_info.lookup_name, state.host_db_info.ip()) &&
               ats_is_ip_loopback(state.host_db_info.ip())) {
      // If it's 127.0.0.1 or ::1 don't bother with hostdb
      Debug("dns", "Skipping DNS lookup for %s because it's loopback",
              state.dns_info.lookup_name);
      state.dns_info.lookup_success = true;

      // Go back
      //call_transact_and_set_next_state(nullptr);
      break;
    } else if (state.http_config_param->use_client_target_addr == 2 && !state.url_remap_success &&
               state.parent_result.result != PARENT_SPECIFIED && state.client_info.is_transparent &&
               state.dns_info.os_addr_style == HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_DEFAULT &&
               ats_is_ip(addr = _root_sm->ua_txn->get_netvc()->get_local_addr())) {
      /* If the connection is client side transparent and the URL
       * was not remapped/directed to parent proxy, we can use the
       * client destination IP address instead of doing a DNS
       * lookup. This is controlled by the 'use_client_target_addr'
       * configuration parameter.
       */
      if (is_debug_tag_set("dns")) {
        ip_text_buffer ipb;
        Debug("dns", "Skipping DNS lookup for client supplied target %s.",
                ats_ip_ntop(addr, ipb, sizeof(ipb)));
      }
      ats_ip_copy(state.host_db_info.ip(), addr);
      if (state.hdr_info.client_request.version_get() == HTTPVersion(0, 9)) {
        state.host_db_info.app.http_data.http_version = HostDBApplicationInfo::HTTP_VERSION_09;
      } else if (state.hdr_info.client_request.version_get() == HTTPVersion(1, 0)) {
        state.host_db_info.app.http_data.http_version = HostDBApplicationInfo::HTTP_VERSION_10;
      } else {
        state.host_db_info.app.http_data.http_version = HostDBApplicationInfo::HTTP_VERSION_11;
      }

      state.dns_info.lookup_success = true;
      // cache this result so we don't have to unreliably duplicate the
      // logic later if the connect fails.
      state.dns_info.os_addr_style = HttpTransact::DNSLookupInfo::OS_Addr::OS_ADDR_TRY_CLIENT;

      // Go back
      //call_transact_and_set_next_state(nullptr);
      break;
    } else if (state.parent_result.result == PARENT_UNDEFINED && state.dns_info.lookup_success) {
      // Already set, and we don't have a parent proxy to lookup
      ink_assert(ats_is_ip(state.host_db_info.ip()));
      Debug("dns", "Skipping DNS lookup, provided by plugin");
      // Go back
      //call_transact_and_set_next_state(nullptr);
      break;
    } else if (state.dns_info.looking_up == HttpTransact::ORIGIN_SERVER && state.http_config_param->no_dns_forward_to_parent &&
               state.parent_result.result != PARENT_UNDEFINED) {
      state.dns_info.lookup_success = true;
      // Go back
      //call_transact_and_set_next_state(nullptr);
      break;
    }

    _return_point = ConnectSM::OSDNSLookup;
    SET_HANDLER(&ConnectSM::state_hostdb_lookup);

    ink_assert(state.dns_info.looking_up != HttpTransact::UNDEFINED_LOOKUP);
    this->do_hostdb_lookup();
    break;
  }
    break;
  case ConnectSM::StartConnect:
    break;
  case ConnectSM::RetryConnect:
    break;
  default:
    ink_release_assert(!"Unknown action");
    break;
  }
}

void 
ConnectSM::start_machine(HttpSM *root_sm, ConnectSM::Action next_action)
{
  _root_sm = root_sm;
  _root_sm
  _next_action = next_action;
  transition_state();
}

///////////////////////////////////////////////////////////////////////////////
// Name       : OSDNSLookup
// Description: called after the DNS lookup of origin server name
//
// Details    :
//
// normally called after Start. may be called more than once, however,
// if the dns lookup fails. this may be if the client does not specify
// the full hostname (e.g. just cnn, instead of www.cnn.com), or because
// it was not possible to resolve the name after several attempts.
//
// the next action depends. since this function is normally called after
// a request has come in, which is valid and does not require an immediate
// response, the next action may just be to open a connection to the
// origin server, or a parent proxy, or the next action may be to do a
// cache lookup, or in the event of an error, the next action may be to
// send a response back to the client.
//
//
// Possible Next States From Here:
// - HttpTransact::PROXY_INTERNAL_CACHE_NOOP;
// - HttpTransact::CACHE_LOOKUP;
// - HttpTransact::SM_ACTION_DNS_LOOKUP;
// - HttpTransact::ORIGIN_SERVER_RAW_OPEN;
// - HttpTransact::ORIGIN_SERVER_OPEN;
//
///////////////////////////////////////////////////////////////////////////////
void
ConnectSM::OSDNSLookup()
{
  static const int max_dns_lookups = 3;
  HttpTransact::State s = &_root_sm->t_state;

  ink_assert(s->dns_info.looking_up == ORIGIN_SERVER);

  Debug("conn_sm", "[OSDNSLookup] This was attempt %d", s->dns_info.attempts);
  ++s->dns_info.attempts;

  // It's never valid to connect *to* INADDR_ANY, so let's reject the request now.
  if (ats_is_ip_any(s->host_db_info.ip())) {
    Debug("conn_sm", "[OSDNSLookup] Invalid request IP: INADDR_ANY");
    // ERROR Return to HttpSM with error
    HttpTransact::build_error_response(s, HTTP_STATUS_BAD_REQUEST, "Bad Destination Address", "request#syntax_error");
    SET_VIA_STRING(VIA_DETAIL_TUNNEL, VIA_DETAIL_TUNNEL_NO_FORWARD);
    set_sm_done(SM_ACTION_SEND_ERROR_CACHE_NOOP, nullptr);
  }

  // detect whether we are about to self loop. the client may have
  // specified the proxy as the origin server (badness).
  // Check if this procedure is already done - YTS Team, yamsat
  if (!s->request_will_not_selfloop) {
    if (HttpTransact::will_this_request_self_loop(s)) {
      Debug("conn_sm", "[OSDNSLookup] request will selfloop - bailing out");
      SET_VIA_STRING(VIA_DETAIL_TUNNEL, VIA_DETAIL_TUNNEL_NO_FORWARD);
      set_sm_done(SM_ACTION_SEND_ERROR_CACHE_NOOP, nullptr);
    }
  }

  if (!s->dns_info.lookup_success) {
    // maybe the name can be expanded (e.g cnn -> www.cnn.com)
    HostNameExpansionError_t host_name_expansion = HttpTransact::try_to_expand_host_name(s);

    switch (host_name_expansion) {
    case RETRY_EXPANDED_NAME:
      // expansion successful, do a dns lookup on expanded name, go through this state again
      ink_release_assert(s->dns_info.attempts < max_dns_lookups);
      return CallOSDNSLookup(s);
      break;
    case EXPANSION_NOT_ALLOWED:
    case EXPANSION_FAILED:
    case DNS_ATTEMPTS_EXHAUSTED:
      if (DNSLookupInfo::OS_Addr::OS_ADDR_TRY_HOSTDB == s->dns_info.os_addr_style) {
        /*
         *  We tried to connect to client target address, failed and tried to use a different addr
         *  No HostDB data, just keep on with the CTA.
         */
        s->dns_info.lookup_success = true;
        s->dns_info.os_addr_style  = DNSLookupInfo::OS_Addr::OS_ADDR_USE_CLIENT;
        Debug("connect_sm", "[OSDNSLookup] DNS lookup unsuccessful, using client target address");
      } else {
        if (host_name_expansion == EXPANSION_NOT_ALLOWED) {
          // config file doesn't allow automatic expansion of host names
          Debug("connect_sm", "[OSDNSLookup] DNS Lookup unsuccessful");
        } else if (host_name_expansion == EXPANSION_FAILED) {
          // not able to expand the hostname. dns lookup failed
          Debug("connect_sm", "[OSDNSLookup] DNS Lookup unsuccessful");
        } else if (host_name_expansion == DNS_ATTEMPTS_EXHAUSTED) {
          // retry attempts exhausted --- can't find dns entry for this host name
          HTTP_RELEASE_ASSERT(s->dns_info.attempts >= max_dns_lookups);
          Debug("connect_sm", "[OSDNSLookup] DNS Lookup unsuccessful");
        }
        // output the DNS failure error message
        SET_VIA_STRING(VIA_DETAIL_TUNNEL, VIA_DETAIL_TUNNEL_NO_FORWARD);
        HttpTransact::build_error_response(s, HTTP_STATUS_BAD_GATEWAY, "Cannot find server.", "connect#dns_failed");
        set_sm_done(SM_ACTION_SEND_ERROR_CACHE_NOOP, nullptr);
      }
      break;
    default:
      ink_assert(!("try_to_expand_hostname returned an unsupported code"));
      break;
    }
    return;
  }
  // ok, so the dns lookup succeeded
  ink_assert(s->dns_info.lookup_success);
  Debug("connect_sm", "[OSDNSLookup] DNS Lookup successful");

  if (DNSLookupInfo::OS_Addr::OS_ADDR_TRY_HOSTDB == s->dns_info.os_addr_style) {
    // We've backed off from a client supplied address and found some
    // HostDB addresses. We use those if they're different from the CTA.
    // In all cases we now commit to client or HostDB for our source.
    if (s->host_db_info.round_robin) {
      HostDBInfo *cta = s->host_db_info.rr()->select_next(&s->current.server->dst_addr.sa);
      if (cta) {
        // found another addr, lock in host DB.
        s->host_db_info           = *cta;
        s->dns_info.os_addr_style = DNSLookupInfo::OS_Addr::OS_ADDR_USE_HOSTDB;
      } else {
        // nothing else there, continue with CTA.
        s->dns_info.os_addr_style = DNSLookupInfo::OS_Addr::OS_ADDR_USE_CLIENT;
      }
    } else if (ats_ip_addr_eq(s->host_db_info.ip(), &s->server_info.dst_addr.sa)) {
      s->dns_info.os_addr_style = DNSLookupInfo::OS_Addr::OS_ADDR_USE_CLIENT;
    } else {
      s->dns_info.os_addr_style = DNSLookupInfo::OS_Addr::OS_ADDR_USE_HOSTDB;
    }
  }

  // Check to see if can fullfill expect requests based on the cached
  // update some state variables with hostdb information that has
  // been provided.
  ats_ip_copy(&s->server_info.dst_addr, s->host_db_info.ip());
  // If the SRV response has a port number, we should honor it. Otherwise we do the port defined in remap
  if (s->dns_info.srv_lookup_success) {
    s->server_info.dst_addr.port() = htons(s->dns_info.srv_port);
  } else if (!s->api_server_addr_set) {
    s->server_info.dst_addr.port() = htons(s->hdr_info.client_request.port_get()); // now we can set the port.
  }
  ats_ip_copy(&s->request_data.dest_ip, &s->server_info.dst_addr);
  get_ka_info_from_host_db(s, &s->server_info, &s->client_info, &s->host_db_info);

  char addrbuf[INET6_ADDRSTRLEN];
  Debug("connect_sm",
           "[OSDNSLookup] DNS lookup for O.S. successful "
           "IP: %s",
           ats_ip_ntop(&s->server_info.dst_addr.sa, addrbuf, sizeof(addrbuf)));

  if (s->redirect_info.redirect_in_process) {
    // If dns lookup was not successful, the code below will handle the error.
    RedirectEnabled::Action action = RedirectEnabled::Action::INVALID;
    if (true == Machine::instance()->is_self(s->host_db_info.ip())) {
      action = s->http_config_param->redirect_actions_self_action;
    } else {
      // Make sure the return value from contains is big enough for a void*.
      intptr_t x{intptr_t(RedirectEnabled::Action::INVALID)};
      ink_release_assert(s->http_config_param->redirect_actions_map != nullptr);
      ink_release_assert(s->http_config_param->redirect_actions_map->contains(s->host_db_info.ip(), reinterpret_cast<void **>(&x)));
      action = static_cast<RedirectEnabled::Action>(x);
    }
    switch (action) {
    case RedirectEnabled::Action::FOLLOW:
      Debug("connect_sm", "[OSDNSLookup] Invalid redirect address. Following");
      break;
    case RedirectEnabled::Action::REJECT:
      Debug("connect_sm", "[OSDNSLookup] Invalid redirect address. Rejecting.");
      HttpTransact::build_error_response(s, HTTP_STATUS_FORBIDDEN, nullptr, "request#syntax_error");
      SET_VIA_STRING(VIA_DETAIL_TUNNEL, VIA_DETAIL_TUNNEL_NO_FORWARD);
      set_sm_done(SM_ACTION_SEND_ERROR_CACHE_NOOP, nullptr);
      break;
    case RedirectEnabled::Action::RETURN:
      Debug("connect_sm", "[OSDNSLookup] Configured to return on invalid redirect address.");
      // fall-through
    default:
      // Return this 3xx to the client as-is.
      Debug("connect_sm", "[OSDNSLookup] Invalid redirect address. Returning.");
      HttpTransact::build_response_copy(s, &s->hdr_info.server_response, &s->hdr_info.client_response, s->client_info.http_version);
      set_sm_done(SM_ACTION_SEND_ERROR_CACHE_NOOP, nullptr);
    }
  }

  // so the dns lookup was a success, but the lookup succeeded on
  // a hostname which was expanded by the traffic server. we should
  // not automatically forward the request to this expanded hostname.
  // return a response to the client with the expanded host name
  // and a tasty little blurb explaining what happened.

  // if a DNS lookup succeeded on a user-defined
  // hostname expansion, forward the request to the expanded hostname.
  // On the other hand, if the lookup succeeded on a www.<hostname>.com
  // expansion, return a 302 response.
  // [amc] Also don't redirect if we backed off using HostDB instead of CTA.
  if (s->dns_info.attempts == max_dns_lookups && s->dns_info.looking_up == ORIGIN_SERVER &&
      DNSLookupInfo::OS_Addr::OS_ADDR_USE_CLIENT != s->dns_info.os_addr_style) {
    Debug("connect_sm", "[OSDNSLookup] DNS name resolution on expansion");
    Debug("connect_sm", "[OSDNSLookup] DNS name resolution on expansion - returning");
    HttpTransact::build_redirect_response(s);
    // s->cache_info.action = CACHE_DO_NO_ACTION;
    set_sm_done(SM_ACTION_INTERNAL_CACHE_NOOP, nullptr);
  }
  // everything succeeded with the DNS lookup so do an API callout
  //   that allows for filtering.  We'll do traffic_server internal
  //   filtering after API filtering

  // After SM_ACTION_DNS_LOOKUP, goto the saved action/state ORIGIN_SERVER_(RAW_)OPEN.
  // Should we skip the StartAccessControl()? why?

  if (s->cdn_remap_complete) {
    Debug("cdn", "This is a late DNS lookup.  We are going to the OS, "
                    "not to HandleFiltering.");

    ink_assert(s->cdn_saved_next_action == SM_ACTION_ORIGIN_SERVER_OPEN ||
               s->cdn_saved_next_action == SM_ACTION_ORIGIN_SERVER_RAW_OPEN);
    Debug("cdn", "outgoing version -- (pre  conversion) %d", s->hdr_info.server_request.m_http->m_version);
    (&s->hdr_info.server_request)->version_set(HTTPVersion(1, 1));
    HttpTransactHeaders::convert_request(s->current.server->http_version, &s->hdr_info.server_request);
    Debug("cdn", "outgoing version -- (post conversion) %d", s->hdr_info.server_request.m_http->m_version);
    set_sm_done(s->cdn_saved_next_action, nullptr);
  } else if (DNSLookupInfo::OS_Addr::OS_ADDR_USE_CLIENT == s->dns_info.os_addr_style ||
             DNSLookupInfo::OS_Addr::OS_ADDR_USE_HOSTDB == s->dns_info.os_addr_style) {
    // we've come back after already trying the server to get a better address
    // and finished with all backtracking - return to trying the server.
    set_sm_done(how_to_open_connection(s), HttpTransact::HandleResponse);
  } else if (s->dns_info.lookup_name[0] <= '9' && s->dns_info.lookup_name[0] >= '0' && s->parent_params->parent_table->hostMatch &&
             !s->http_config_param->no_dns_forward_to_parent) {
    // note, broken logic: ACC fudges the OR stmt to always be true,
    // 'AuthHttpAdapter' should do the rev-dns if needed, not here .
    //TRANSACT_RETURN(SM_ACTION_DNS_REVERSE_LOOKUP, HttpTransact::StartAccessControl);
    _next_action = DnsReverseLookup;
  } else {
    if (s->force_dns) {
      StartAccessControl(s); // If skip_dns is enabled and no ip based rules in cache.config and parent.config
      // Access Control is called after DNS response
    } else {
      if ((s->cache_info.action == CACHE_DO_NO_ACTION) &&
          (((s->hdr_info.client_request.presence(MIME_PRESENCE_RANGE) && !s->txn_conf->cache_range_write) ||
            s->range_setup == RANGE_NOT_SATISFIABLE || s->range_setup == RANGE_NOT_HANDLED))) {
        TRANSACT_RETURN(SM_ACTION_API_OS_DNS, HandleCacheOpenReadMiss);
      } else if (!s->txn_conf->cache_http || s->cache_lookup_result == HttpTransact::CACHE_LOOKUP_SKIPPED) {
        TRANSACT_RETURN(SM_ACTION_API_OS_DNS, LookupSkipOpenServer);
        // DNS Lookup is done after LOOKUP Skipped  and after we get response
        // from the DNS we need to call LookupSkipOpenServer
      } else if (is_cache_hit(s->cache_lookup_result)) {
        // DNS lookup is done if the content is state need to call handle cache open read hit
        TRANSACT_RETURN(SM_ACTION_API_OS_DNS, HandleCacheOpenReadHit);
      } else if (s->cache_lookup_result == CACHE_LOOKUP_MISS || s->cache_info.action == CACHE_DO_NO_ACTION) {
        TRANSACT_RETURN(SM_ACTION_API_OS_DNS, HandleCacheOpenReadMiss);
        // DNS lookup is done if the lookup failed and need to call Handle Cache Open Read Miss
      } else {
        build_error_response(s, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Invalid Cache Lookup result", "default");
        Log::error("HTTP: Invalid CACHE LOOKUP RESULT : %d", s->cache_lookup_result);
        TRANSACT_RETURN(SM_ACTION_SEND_ERROR_CACHE_NOOP, nullptr);
      }
    }
  }
}

int
ConnectSM::state_hostdb_lookup(int event, void *data)
{
  HttpTransact::State s = &_root_sm->t_state;
  STATE_ENTER(&HttpSM::state_hostdb_lookup, event);
  //    ink_assert (m_origin_server_vc == 0);
  // REQ_FLAVOR_SCHEDULED_UPDATE can be transformed into
  // REQ_FLAVOR_REVPROXY
  ink_assert(state.req_flavor == HttpTransact::REQ_FLAVOR_SCHEDULED_UPDATE ||
             state.req_flavor == HttpTransact::REQ_FLAVOR_REVPROXY || ua_entry->vc != nullptr);

  switch (event) {
  case EVENT_HOST_DB_LOOKUP:
    pending_action = nullptr;
    HttpTransact::process_hostdb_info(static_cast<HostDBInfo *>(data));
    call_transact_and_set_next_state(nullptr);
    break;
  case EVENT_SRV_LOOKUP: {
    pending_action = nullptr;
    process_srv_info(static_cast<HostDBInfo *>(data));

    char *host_name = state.dns_info.srv_lookup_success ? state.dns_info.srv_hostname : state.dns_info.lookup_name;
    HostDBProcessor::Options opt;
    opt.port  = state.dns_info.srv_lookup_success ? state.dns_info.srv_port : state.server_info.dst_addr.host_order_port();
    opt.flags = (state.cache_info.directives.does_client_permit_dns_storing) ? HostDBProcessor::HOSTDB_DO_NOT_FORCE_DNS :
                                                                                 HostDBProcessor::HOSTDB_FORCE_DNS_RELOAD;
    opt.timeout        = (state.api_txn_dns_timeout_value != -1) ? state.api_txn_dns_timeout_value : 0;
    opt.host_res_style = ats_host_res_from(_root_sm->ua_txn->get_netvc()->get_local_addr()->sa_family, state.txn_conf->host_res_data.order);

    Action *dns_lookup_action_handle =
      hostDBProcessor.getbyname_imm(this, (cb_process_result_pfn)&HttpSM::process_hostdb_info, host_name, 0, opt);
    if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
      ink_assert(!pending_action);
      pending_action = dns_lookup_action_handle;
    } else {
      call_transact_and_set_next_state(nullptr);
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
ConnectSM::do_hostdb_lookup()
{
  HttpTransact::State s = &_root_sm->t_state;
  ink_assert(state.dns_info.lookup_name != nullptr);
  ink_assert(pending_action == nullptr);

  _root_sm->milestones[TS_MILESTONE_DNS_LOOKUP_BEGIN] = Thread::get_hrtime();

  if (state.txn_conf->srv_enabled) {
    char d[MAXDNAME];

    // Look at the next_hop_scheme to determine what scheme to put in the SRV lookup
    unsigned int scheme_len = sprintf(d, "_%s._tcp.", hdrtoken_index_to_wks(state.next_hop_scheme));
    ink_strlcpy(d + scheme_len, state.server_info.name, sizeof(d) - scheme_len);

    Debug("dns_srv", "Beginning lookup of SRV records for origin %s", d);

    HostDBProcessor::Options opt;
    if (state.api_txn_dns_timeout_value != -1) {
      opt.timeout = state.api_txn_dns_timeout_value;
    }
    Action *srv_lookup_action_handle =
      hostDBProcessor.getSRVbyname_imm(this, (cb_process_result_pfn)&HttpSM::process_srv_info, d, 0, opt);

    if (srv_lookup_action_handle != ACTION_RESULT_DONE) {
      ink_assert(!pending_action);
      pending_action = srv_lookup_action_handle;
    } else {
      char *host_name = state.dns_info.srv_lookup_success ? state.dns_info.srv_hostname : state.dns_info.lookup_name;
      opt.port        = state.dns_info.srv_lookup_success ?
                   state.dns_info.srv_port :
                   state.server_info.dst_addr.isValid() ? state.server_info.dst_addr.host_order_port() :
                                                            state.hdr_info.client_request.port_get();
      opt.flags = (state.cache_info.directives.does_client_permit_dns_storing) ? HostDBProcessor::HOSTDB_DO_NOT_FORCE_DNS :
                                                                                   HostDBProcessor::HOSTDB_FORCE_DNS_RELOAD;
      opt.timeout = (state.api_txn_dns_timeout_value != -1) ? state.api_txn_dns_timeout_value : 0;
      opt.host_res_style =
        ats_host_res_from(ua_txn->get_netvc()->get_local_addr()->sa_family, state.txn_conf->host_res_data.order);

      Action *dns_lookup_action_handle =
        hostDBProcessor.getbyname_imm(this, (cb_process_result_pfn)&HttpSM::process_hostdb_info, host_name, 0, opt);
      if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
        ink_assert(!pending_action);
        pending_action = dns_lookup_action_handle;
      } else {
        call_transact_and_set_next_state(nullptr);
      }
    }
    return;
  } else { /* we aren't using SRV stuff... */
    Debug("http_seq", "[HttpSM::do_hostdb_lookup] Doing DNS Lookup");

    // If there is not a current server, we must be looking up the origin
    //  server at the beginning of the transaction
    int server_port = 0;
    if (state.current.server && state.current.server->dst_addr.isValid()) {
      server_port = state.current.server->dst_addr.host_order_port();
    } else if (state.server_info.dst_addr.isValid()) {
      server_port = state.server_info.dst_addr.host_order_port();
    } else {
      server_port = state.hdr_info.client_request.port_get();
    }

    if (state.api_txn_dns_timeout_value != -1) {
      Debug("http_timeout", "beginning DNS lookup. allowing %d mseconds for DNS lookup", state.api_txn_dns_timeout_value);
    }

    HostDBProcessor::Options opt;
    opt.port  = server_port;
    opt.flags = (state.cache_info.directives.does_client_permit_dns_storing) ? HostDBProcessor::HOSTDB_DO_NOT_FORCE_DNS :
                                                                                 HostDBProcessor::HOSTDB_FORCE_DNS_RELOAD;
    opt.timeout = (state.api_txn_dns_timeout_value != -1) ? state.api_txn_dns_timeout_value : 0;

    opt.host_res_style = ats_host_res_from(ua_txn->get_netvc()->get_local_addr()->sa_family, state.txn_conf->host_res_data.order);

    Action *dns_lookup_action_handle = hostDBProcessor.getbyname_imm(this, (cb_process_result_pfn)&HttpSM::process_hostdb_info,
                                                                     state.dns_info.lookup_name, 0, opt);

    if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
      ink_assert(!pending_action);
      pending_action = dns_lookup_action_handle;
    } else {
      call_transact_and_set_next_state(nullptr);
    }
    return;
  }
  ink_assert(!"not reached");
  return;
}

void
HttpSM::do_hostdb_reverse_lookup()
{
  HttpTransact::State s = &_root_sm->t_state;
  ink_assert(state.dns_info.lookup_name != nullptr);
  ink_assert(pending_action == nullptr);

  Debug("http_seq", "[HttpSM::do_hostdb_reverse_lookup] Doing reverse DNS Lookup");

  IpEndpoint addr;
  ats_ip_pton(state.dns_info.lookup_name, &addr.sa);
  Action *dns_lookup_action_handle = hostDBProcessor.getbyaddr_re(this, &addr.sa);

  if (dns_lookup_action_handle != ACTION_RESULT_DONE) {
    ink_assert(!pending_action);
    pending_action = dns_lookup_action_handle;
  }
  return;
}

