/** @file

  Http2ClientSession.

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

#include "Http2ClientSession.h"
#include "HttpDebugNames.h"
#include "tscore/ink_base64.h"
#include "Http2CommonSessionInternal.h"

ClassAllocator<Http2ClientSession> http2ClientSessionAllocator("http2ClientSessionAllocator");

static int
send_connection_event(Continuation *cont, int event, void *edata)
{
  SCOPED_MUTEX_LOCK(lock, cont->mutex, this_ethread());
  return cont->handleEvent(event, edata);
}

Http2ClientSession::Http2ClientSession() = default;

void
Http2ClientSession::destroy()
{
  if (!in_destroy) {
    in_destroy = true;
    REMEMBER(NO_EVENT, this->recursion)
    Http2SsnDebug("session destroy");
    // Let everyone know we are going down
    do_api_callout(TS_HTTP_SSN_CLOSE_HOOK);
  }
}

void
Http2ClientSession::free()
{
  if (Http2CommonSession::free(this)) {
    HTTP2_DECREMENT_THREAD_DYN_STAT(HTTP2_STAT_CURRENT_CLIENT_SESSION_COUNT, this->mutex->thread_holding);
    super::free();
    THREAD_FREE(this, http2ClientSessionAllocator, this_ethread());
  }
}

void
Http2ClientSession::start()
{
  SCOPED_MUTEX_LOCK(lock, this->mutex, this_ethread());

  SET_HANDLER(&Http2ClientSession::main_event_handler);
  HTTP2_SET_SESSION_HANDLER(&Http2ClientSession::state_read_connection_preface);

  VIO *read_vio = this->do_io_read(this, INT64_MAX, this->read_buffer);
  write_vio     = this->do_io_write(this, INT64_MAX, this->sm_writer);

  this->connection_state.init();
  send_connection_event(&this->connection_state, HTTP2_SESSION_EVENT_INIT, static_cast<Http2CommonSession *>(this));

  if (this->_reader->is_read_avail_more_than(0)) {
    this->handleEvent(VC_EVENT_READ_READY, read_vio);
  }
}

void
Http2ClientSession::new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader)
{
  ink_assert(new_vc->mutex->thread_holding == this_ethread());
  HTTP2_INCREMENT_THREAD_DYN_STAT(HTTP2_STAT_CURRENT_CLIENT_SESSION_COUNT, new_vc->mutex->thread_holding);
  HTTP2_INCREMENT_THREAD_DYN_STAT(HTTP2_STAT_TOTAL_CLIENT_CONNECTION_COUNT, new_vc->mutex->thread_holding);
  this->_milestones.mark(Http2SsnMilestone::OPEN);

  // Unique client session identifier.
  this->con_id = ProxySession::next_connection_id();
  this->_vc    = new_vc;
  _vc->set_inactivity_timeout(HRTIME_SECONDS(Http2::accept_no_activity_timeout));
  this->schedule_event = nullptr;
  this->mutex          = new_vc->mutex;
  this->in_destroy     = false;

  this->connection_state.mutex = this->mutex;

  SSLNetVConnection *ssl_vc = dynamic_cast<SSLNetVConnection *>(new_vc);
  if (ssl_vc != nullptr) {
    this->read_from_early_data = ssl_vc->read_from_early_data;
    Debug("ssl_early_data", "read_from_early_data = %" PRId64, this->read_from_early_data);
  }

  Http2SsnDebug("session born, netvc %p", this->_vc);

  this->_vc->set_tcp_congestion_control(CLIENT_SIDE);

  this->read_buffer             = iobuf ? iobuf : new_MIOBuffer(HTTP2_HEADER_BUFFER_SIZE_INDEX);
  this->read_buffer->water_mark = connection_state.server_settings.get(HTTP2_SETTINGS_MAX_FRAME_SIZE);
  this->_reader                 = reader ? reader : this->read_buffer->alloc_reader();

  // Set write buffer size to max size of TLS record (16KB)
  this->write_buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_16K);
  this->sm_writer    = this->write_buffer->alloc_reader();

  this->_handle_if_ssl(new_vc);

  do_api_callout(TS_HTTP_SSN_START_HOOK);
}

void
Http2ClientSession::set_upgrade_context(HTTPHdr *h)
{
  upgrade_context.req_header = new HTTPHdr();
  upgrade_context.req_header->copy(h);

  MIMEField *settings = upgrade_context.req_header->field_find(MIME_FIELD_HTTP2_SETTINGS, MIME_LEN_HTTP2_SETTINGS);
  ink_release_assert(settings != nullptr);
  int svlen;
  const char *sv = settings->value_get(&svlen);

  if (sv && svlen > 0) {
    // Maybe size of data decoded by Base64URL is lower than size of encoded data.
    unsigned char out_buf[svlen];
    size_t decoded_len;
    ats_base64_decode(sv, svlen, out_buf, svlen, &decoded_len);
    for (size_t nbytes = 0; nbytes < decoded_len; nbytes += HTTP2_SETTINGS_PARAMETER_LEN) {
      Http2SettingsParameter param;
      if (!http2_parse_settings_parameter(make_iovec(out_buf + nbytes, HTTP2_SETTINGS_PARAMETER_LEN), param) ||
          !http2_settings_parameter_is_valid(param)) {
        // TODO ignore incoming invalid parameters and send suitable SETTINGS
        // frame.
      }
      upgrade_context.client_settings.set(static_cast<Http2SettingsIdentifier>(param.id), param.value);
    }
  }

  // Such intermediaries SHOULD also remove other connection-
  // specific header fields, such as Keep-Alive, Proxy-Connection,
  // Transfer-Encoding and Upgrade, even if they are not nominated by
  // Connection.
  upgrade_context.req_header->field_delete(MIME_FIELD_CONNECTION, MIME_LEN_CONNECTION);
  upgrade_context.req_header->field_delete(MIME_FIELD_KEEP_ALIVE, MIME_LEN_KEEP_ALIVE);
  upgrade_context.req_header->field_delete(MIME_FIELD_PROXY_CONNECTION, MIME_LEN_PROXY_CONNECTION);
  upgrade_context.req_header->field_delete(MIME_FIELD_TRANSFER_ENCODING, MIME_LEN_TRANSFER_ENCODING);
  upgrade_context.req_header->field_delete(MIME_FIELD_UPGRADE, MIME_LEN_UPGRADE);
  upgrade_context.req_header->field_delete(MIME_FIELD_HTTP2_SETTINGS, MIME_LEN_HTTP2_SETTINGS);
}

// XXX Currently, we don't have a half-closed state, but we will need to
// implement that. After we send a GOAWAY, there
// are scenarios where we would like to complete the outstanding streams.

void
Http2ClientSession::do_io_close(int alerrno)
{
  REMEMBER(NO_EVENT, this->recursion)
  Http2SsnDebug("session closed");

  ink_assert(this->mutex->thread_holding == this_ethread());
  send_connection_event(&this->connection_state, HTTP2_SESSION_EVENT_FINI, this);

  {
    SCOPED_MUTEX_LOCK(lock, this->connection_state.mutex, this_ethread());
    this->connection_state.release_stream();
  }

  this->clear_session_active();

  // Clean up the write VIO in case of inactivity timeout
  this->do_io_write(nullptr, 0, nullptr);
}

int
Http2ClientSession::main_event_handler(int event, void *edata)
{
  ink_assert(this->mutex->thread_holding == this_ethread());
  int retval;

  recursion++;

  Event *e = static_cast<Event *>(edata);
  if (e == schedule_event) {
    schedule_event = nullptr;
  }

  switch (event) {
  case VC_EVENT_READ_COMPLETE:
  case VC_EVENT_READ_READY: {
    bool is_zombie = connection_state.get_zombie_event() != nullptr;
    retval         = (this->*session_handler)(event, edata);
    if (is_zombie && connection_state.get_zombie_event() != nullptr) {
      Warning("Processed read event for zombie session %" PRId64, connection_id());
    }
    break;
  }

  case HTTP2_SESSION_EVENT_REENABLE:
    // VIO will be reenableed in this handler
    retval = (this->*session_handler)(VC_EVENT_READ_READY, static_cast<VIO *>(e->cookie));
    // Clear the event after calling session_handler to not reschedule REENABLE in it
    this->_reenable_event = nullptr;
    break;

  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ERROR:
  case VC_EVENT_EOS:
    this->set_dying_event(event);
    this->do_io_close();
    if (_vc != nullptr) {
      _vc->do_io_close();
      _vc = nullptr;
    }
    retval = 0;
    break;

  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE:
    this->connection_state.restart_streams();

    retval = 0;
    break;

  case HTTP2_SESSION_EVENT_XMIT:
  default:
    Http2SsnDebug("unexpected event=%d edata=%p", event, edata);
    ink_release_assert(0);
    retval = 0;
    break;
  }

  if (!this->is_draining() && this->connection_state.get_shutdown_reason() == Http2ErrorCode::HTTP2_ERROR_MAX) {
    this->connection_state.set_shutdown_state(HTTP2_SHUTDOWN_NONE);
  }

  if (this->connection_state.get_shutdown_state() == HTTP2_SHUTDOWN_NONE) {
    if (this->is_draining()) { // For a case we already checked Connection header and it didn't exist
      Http2SsnDebug("Preparing for graceful shutdown because of draining state");
      this->connection_state.set_shutdown_state(HTTP2_SHUTDOWN_NOT_INITIATED);
    } else if (this->connection_state.get_stream_error_rate() >
               Http2::stream_error_rate_threshold) { // For a case many stream errors happened
      ip_port_text_buffer ipb;
      const char *client_ip = ats_ip_ntop(get_remote_addr(), ipb, sizeof(ipb));
      Warning("HTTP/2 session error client_ip=%s session_id=%" PRId64
              " closing a connection, because its stream error rate (%f) exceeded the threshold (%f)",
              client_ip, connection_id(), this->connection_state.get_stream_error_rate(), Http2::stream_error_rate_threshold);
      Http2SsnDebug("Preparing for graceful shutdown because of a high stream error rate");
      cause_of_death = Http2SessionCod::HIGH_ERROR_RATE;
      this->connection_state.set_shutdown_state(HTTP2_SHUTDOWN_NOT_INITIATED, Http2ErrorCode::HTTP2_ERROR_ENHANCE_YOUR_CALM);
    }
  }

  if (this->connection_state.get_shutdown_state() == HTTP2_SHUTDOWN_NOT_INITIATED) {
    send_connection_event(&this->connection_state, HTTP2_SESSION_EVENT_SHUTDOWN_INIT, this);
  }

  recursion--;
  if (!connection_state.is_recursing() && this->recursion == 0 && kill_me) {
    this->free();
  }
  return retval;
}

void
Http2ClientSession::increment_current_active_connections_stat()
{
  HTTP2_INCREMENT_THREAD_DYN_STAT(HTTP2_STAT_CURRENT_ACTIVE_CLIENT_CONNECTION_COUNT, this_ethread());
}

void
Http2ClientSession::decrement_current_active_connections_stat()
{
  HTTP2_DECREMENT_THREAD_DYN_STAT(HTTP2_STAT_CURRENT_ACTIVE_CLIENT_CONNECTION_COUNT, this_ethread());
}

sockaddr const *
Http2ClientSession::get_remote_addr() const
{
  return _vc ? _vc->get_remote_addr() : &cached_client_addr.sa;
}

sockaddr const *
Http2ClientSession::get_local_addr()
{
  return _vc ? _vc->get_local_addr() : &cached_local_addr.sa;
}

int
Http2ClientSession::get_transact_count() const
{
  return connection_state.get_stream_requests();
}

const char *
Http2ClientSession::get_protocol_string() const
{
  return "http/2";
}

void
Http2ClientSession::release(ProxyTransaction *trans)
{
}

int
Http2ClientSession::populate_protocol(std::string_view *result, int size) const
{
  int retval = 0;
  if (size > retval) {
    result[retval++] = IP_PROTO_TAG_HTTP_2_0;
    if (size > retval) {
      retval += super::populate_protocol(result + retval, size - retval);
    }
  }
  return retval;
}

const char *
Http2ClientSession::protocol_contains(std::string_view prefix) const
{
  const char *retval = nullptr;

  if (prefix.size() <= IP_PROTO_TAG_HTTP_2_0.size() && strncmp(IP_PROTO_TAG_HTTP_2_0.data(), prefix.data(), prefix.size()) == 0) {
    retval = IP_PROTO_TAG_HTTP_2_0.data();
  } else {
    retval = super::protocol_contains(prefix);
  }
  return retval;
}

ProxySession *
Http2ClientSession::get_proxy_session()
{
  return this;
}
