/** @file

  Http2ServerSession.cc

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

#include "Http2ServerSession.h"
#include "../http/HttpSessionManager.h"

ClassAllocator<Http2ServerSession> http2ServerSessionAllocator("http2ServerSessionAllocator");

#define Http2SsnDebug(fmt, ...) SsnDebug(this, "http2_ss", "[%" PRId64 "] " fmt, this->connection_id(), ##__VA_ARGS__)

void
Http2ServerSession::free()
{
  if (connection_state.is_recursing() || this->is_recursing()) {
    return;
  }
  super::free();
  THREAD_FREE(this, http2ServerSessionAllocator, this_ethread());
}

void 
Http2ServerSession::attach_transaction(HttpSM *attach_sm) 
{
  // In == client side
  Http2StreamId latest_id = connection_state.get_latest_stream_id_in();
  Http2StreamId stream_id =  (latest_id == 0) ? 1 : latest_id + 2;
  this->set_session_active();

  // Create a new stream/transaction
  Http2Error error(Http2ErrorClass::HTTP2_ERROR_CLASS_NONE);
  Http2Stream *stream     = connection_state.create_stream(stream_id, error, true);

  // Then wire it into the state machine as the server_txn
  stream->attach_transaction(attach_sm);
}

void
Http2ServerSession::new_connection(NetVConnection *new_vc, MIOBuffer *iobuf, IOBufferReader *reader, bool backdoor)
{
  ink_assert(new_vc->mutex->thread_holding == this_ethread());

  // HTTP/2 for the backdoor connections? Let's not deal woth that yet.
  ink_release_assert(backdoor == false);

  // Unique client session identifier.
  this->con_id    = ProxySession::next_connection_id();
  this->client_vc = new_vc;
  client_vc->set_inactivity_timeout(HRTIME_SECONDS(Http2::no_activity_timeout_in));
  this->schedule_event = nullptr;
  this->mutex          = new_vc->mutex;
  this->in_destroy     = false;

  Http2SsnDebug("session born, netvc %p", this->client_vc);

  this->client_vc->set_tcp_congestion_control(SERVER_SIDE);

  this->read_buffer             = iobuf ? iobuf : new_MIOBuffer(HTTP2_HEADER_BUFFER_SIZE_INDEX);
  this->read_buffer->water_mark = connection_state.server_settings.get(HTTP2_SETTINGS_MAX_FRAME_SIZE);
  this->sm_reader               = reader ? reader : this->read_buffer->alloc_reader();
  this->h2_pushed_urls          = ink_hash_table_create(InkHashTableKeyType_String);
  this->h2_pushed_urls_size     = 0;

  this->write_buffer = new_MIOBuffer(HTTP2_HEADER_BUFFER_SIZE_INDEX);
  this->sm_writer    = this->write_buffer->alloc_reader();

  this->set_session_active();

  // Server side session hooks not yet wired up.
  //do_api_callout(TS_HTTP_SSN_START_HOOK);
  //

  SET_HANDLER(&Http2Session::main_event_handler);
  this->session_handler = &Http2Session::state_start_frame_read;

  this->connection_state.mutex = this->mutex;
  this->connection_state.init();

  // 3.5 HTTP/2 Connection Preface. Upon establishment of a TCP connection and
  // determination that HTTP/2 will be used by both peers, each endpoint MUST
  // send a connection preface as a final confirmation ...
  // This is the preface string sent by the client
  write_vio = this->do_io_write(this, INT64_MAX, this->sm_writer);
  this->write_buffer->write(HTTP2_CONNECTION_PREFACE, HTTP2_CONNECTION_PREFACE_LEN);
  total_write_len += HTTP2_CONNECTION_PREFACE_LEN;
  write_vio->nbytes = total_write_len;
  write_reenable();
  Http2SsnDebug("Sent Connection Preface");

  connection_state.handleEvent(HTTP2_SESSION_EVENT_INIT, this);

  VIO *read_vio  = this->do_io_read(this, INT64_MAX, this->read_buffer);
  this->handleEvent(VC_EVENT_READ_READY, read_vio);
}

void
Http2ServerSession::add_session()
{
  if (!allocating_pool) {
    httpSessionManager.add_session(this);
  }
}

void
Http2ServerSession::do_io_close(int alerrno)
{
  // Remove us from the session_table
  if (allocating_pool) {
    allocating_pool->removeSession(this);
    allocating_pool = nullptr;
  }
  
  super::do_io_close(alerrno);
}
