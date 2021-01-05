/** @file

  Http2CommonSession.

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

#include "HTTP2.h"
#include "ProxySession.h"
#include "Http2ConnectionState.h"
#include "Http2Frame.h"

// Name                       Edata                 Description
// HTTP2_SESSION_EVENT_INIT   Http2CommonSession *  HTTP/2 session is born
// HTTP2_SESSION_EVENT_FINI   Http2CommonSession *  HTTP/2 session is ended
// HTTP2_SESSION_EVENT_RECV   Http2Frame *          Received a frame
// HTTP2_SESSION_EVENT_XMIT   Http2Frame *          Send this frame

#define HTTP2_SESSION_EVENT_INIT (HTTP2_SESSION_EVENTS_START + 1)
#define HTTP2_SESSION_EVENT_FINI (HTTP2_SESSION_EVENTS_START + 2)
#define HTTP2_SESSION_EVENT_RECV (HTTP2_SESSION_EVENTS_START + 3)
#define HTTP2_SESSION_EVENT_XMIT (HTTP2_SESSION_EVENTS_START + 4)
#define HTTP2_SESSION_EVENT_SHUTDOWN_INIT (HTTP2_SESSION_EVENTS_START + 5)
#define HTTP2_SESSION_EVENT_SHUTDOWN_CONT (HTTP2_SESSION_EVENTS_START + 6)
#define HTTP2_SESSION_EVENT_REENABLE (HTTP2_SESSION_EVENTS_START + 7)

enum class Http2SessionCod : int {
  NOT_PROVIDED,
  HIGH_ERROR_RATE,
};

enum class Http2SsnMilestone {
  OPEN = 0,
  CLOSE,
  LAST_ENTRY,
};

size_t const HTTP2_HEADER_BUFFER_SIZE_INDEX = CLIENT_CONNECTION_FIRST_READ_BUFFER_SIZE_INDEX;

// To support Upgrade: h2c
struct Http2UpgradeContext {
  Http2UpgradeContext() {}
  ~Http2UpgradeContext()
  {
    if (req_header) {
      req_header->clear();
      delete req_header;
    }
  }

  // Modified request header
  HTTPHdr *req_header = nullptr;

  // Decoded HTTP2-Settings Header Field
  Http2ConnectionSettings client_settings;
};

class Http2CommonSession
{
public:
  using SessionHandler = int (Http2CommonSession::*)(int, void *);

  bool free(ProxySession *ssn);

  // Record history from Http2ConnectionState
  void remember(const SourceLocation &location, int event, int reentrant = NO_REENTRANT);

  bool is_recursing() const;
  void set_half_close_local_flag(bool flag);
  bool get_half_close_local_flag() const;
  void set_dying_event(int event);
  int get_dying_event() const;
  bool ready_to_free() const;
  bool is_url_pushed(const char *url, int url_len);
  void add_url_to_pushed_table(const char *url, int url_len);
  int64_t xmit(const Http2TxFrame &frame, bool flush = true);
  virtual void received_setting();
  void flush();

  int64_t get_connection_id();
  Ptr<ProxyMutex> &get_mutex();
  NetVConnection *get_netvc();
  void do_clear_session_active();

  int64_t write_avail();
  int64_t write_buffer_size();

  virtual ProxySession *get_proxy_session() = 0;
  // more methods
  void write_reenable();

  ///////////////////
  // Variables
  Http2ConnectionState connection_state;

protected:
  SessionHandler session_handler = nullptr;

  Event *_reenable_event = nullptr;
  int recursion          = 0;

  History<HISTORY_DEFAULT_SIZE> _history;
  Milestones<Http2SsnMilestone, static_cast<size_t>(Http2SsnMilestone::LAST_ENTRY)> _milestones;

  MIOBuffer *write_buffer = nullptr;
  MIOBuffer *read_buffer  = nullptr;
  VIO *write_vio          = nullptr;
  IOBufferReader *_reader = nullptr;

  std::unordered_set<std::string> *_h2_pushed_urls = nullptr;

  int64_t total_write_len = 0;

  bool half_close_local = false;

  int _n_frame_read = 0;

  uint32_t _pending_sending_data_size = 0;

  int64_t read_from_early_data        = 0;
  bool cur_frame_from_early_data      = false;
  IOBufferReader *sm_writer           = nullptr;
  Http2FrameHeader current_hdr        = {0, 0, 0, 0};
  uint32_t _write_size_threshold      = 0;
  uint32_t _write_time_threshold      = 100;
  ink_hrtime _write_buffer_last_flush = 0;

  int dying_event                = 0;
  bool kill_me                   = false;
  Http2SessionCod cause_of_death = Http2SessionCod::NOT_PROVIDED;

protected:
  int state_read_connection_preface(int, void *);
  int state_start_frame_read(int, void *);
  int do_start_frame_read(Http2ErrorCode &ret_error);
  int state_complete_frame_read(int, void *);
  int do_complete_frame_read();
  // state_start_frame_read and state_complete_frame_read are set up as
  // event handler.  Both feed into state_process_frame_read which may iterate
  // if there are multiple frames ready on the wire
  int state_process_frame_read(int event, VIO *vio, bool inside_frame);
  bool _should_do_something_else();
};

inline bool
Http2CommonSession::is_recursing() const
{
  return recursion > 0;
}

inline bool
Http2CommonSession::get_half_close_local_flag() const
{
  return half_close_local;
}

inline void
Http2CommonSession::set_dying_event(int event)
{
  dying_event = event;
}

inline int
Http2CommonSession::get_dying_event() const
{
  return dying_event;
}

inline bool
Http2CommonSession::ready_to_free() const
{
  return kill_me;
}

inline bool
Http2CommonSession::is_url_pushed(const char *url, int url_len)
{
  if (_h2_pushed_urls == nullptr) {
    return false;
  }

  return _h2_pushed_urls->find(url) != _h2_pushed_urls->end();
}

inline int64_t
Http2CommonSession::get_connection_id()
{
  return get_proxy_session()->connection_id();
}

inline Ptr<ProxyMutex> &
Http2CommonSession::get_mutex()
{
  return get_proxy_session()->mutex;
}

inline NetVConnection *
Http2CommonSession::get_netvc()
{
  return get_proxy_session()->get_netvc();
}

inline void
Http2CommonSession::do_clear_session_active()
{
  get_proxy_session()->clear_session_active();
}

inline int64_t
Http2CommonSession::write_buffer_size()
{
  return write_buffer->max_read_avail();
}

inline void
Http2CommonSession::received_setting()
{
}
