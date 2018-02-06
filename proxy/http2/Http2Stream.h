/** @file

  Http2Stream.h

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

#ifndef __HTTP2_STREAM_H__
#define __HTTP2_STREAM_H__

#include "HTTP2.h"
#include "../ProxyTransaction.h"
#include "Http2DebugNames.h"
#include "../http/HttpTunnel.h" // To get ChunkedHandler
#include "Http2DependencyTree.h"

class Http2Stream;
class Http2ConnectionState;

typedef Http2DependencyTree::Tree<Http2Stream *> DependencyTree;

class Http2Stream : public ProxyTransaction
{
public:
  typedef ProxyTransaction super; ///< Parent type.
  Http2Stream(Http2StreamId sid = 0, ssize_t initial_rwnd = Http2::initial_window_size) : client_rwnd(initial_rwnd), _id(sid)
  {
    SET_HANDLER(&Http2Stream::main_event_handler);
  }

  /**
   * Initiaiting_connection is true if ATS is sending the request header and receivng the respones
   */
  void
  init(Http2StreamId sid, ssize_t initial_rwnd, bool initiating_connection)
  {
    _id               = sid;
    _start_time       = Thread::get_hrtime();
    _thread           = this_ethread();
    _state = Http2StreamState::HTTP2_STREAM_STATE_IDLE;
    this->client_rwnd = initial_rwnd;
    this->initiating_flag = initiating_connection;
    HTTP2_INCREMENT_THREAD_DYN_STAT(HTTP2_STAT_CURRENT_CLIENT_STREAM_COUNT, _thread);
    HTTP2_INCREMENT_THREAD_DYN_STAT(HTTP2_STAT_TOTAL_CLIENT_STREAM_COUNT, _thread);
    sm_reader = recv_reader = recv_buffer.alloc_reader();
    http_parser_init(&http_parser);
    // FIXME: Are you sure? every "stream" needs recv_header?
    if (initiating_flag) { // Flip the sense of the expected headers.  Fix naming later
      _recv_header.create(HTTP_TYPE_RESPONSE);
      _send_header.create(HTTP_TYPE_REQUEST);
    } else {
      _recv_header.create(HTTP_TYPE_REQUEST);
      _send_header.create(HTTP_TYPE_RESPONSE);
    }
  }

  ~Http2Stream() { this->destroy(); }
  int main_event_handler(int event, void *edata);

  void destroy() override;

  bool
  is_body_done() const
  {
    return body_done;
  }

  void
  mark_body_done()
  {
    body_done = true;
  }

  void
  update_sent_count(unsigned num_bytes)
  {
    bytes_sent += num_bytes;
    this->write_vio.ndone += num_bytes;
  }

  Http2StreamId
  get_id() const
  {
    return _id;
  }

  int
  get_transaction_id() const override
  {
    return _id;
  }

  Http2StreamState
  get_state() const
  {
    return _state;
  }

  bool change_state(uint8_t type, uint8_t flags);
  void attach_transaction(HttpSM *attach_sm) override
  {
    super::attach_transaction(attach_sm);
    // We are now effectively open and ready for business
    _state = Http2StreamState::HTTP2_STREAM_STATE_IDLE;
  }

  void
  set_id(Http2StreamId sid)
  {
    _id = sid;
  }

  void
  update_initial_rwnd(Http2WindowSize new_size)
  {
    client_rwnd = new_size;
  }

  bool
  has_trailing_header() const
  {
    return trailing_header;
  }

  void
  set_trailing_header()
  {
    trailing_header = true;
  }

  void
  set_recv_headers(HTTPHdr &h2_headers)
  {
    _recv_header.copy(&h2_headers);
  }

  // Check entire DATA payload length if content-length: header is exist
  void
  increment_data_length(uint64_t length)
  {
    data_length += length;
  }

  bool
  payload_length_is_valid() const
  {
    uint32_t content_length = _recv_header.get_content_length();
    return content_length == 0 || content_length == data_length;
  }

  Http2ErrorCode decode_header_blocks(HpackHandle &hpack_handle, uint32_t maximum_table_size);
  void recv_headers(Http2ConnectionState &cstate);
  VIO *do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf) override;
  VIO *do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *abuffer, bool owner = false) override;
  void do_io_close(int lerrno = -1) override;
  void initiating_close();
  void terminate_if_possible();
  void do_io_shutdown(ShutdownHowTo_t) override {}
  void update_read_request(int64_t read_len, bool send_update, bool check_eos = false);
  bool update_write_request(IOBufferReader *buf_reader, int64_t write_len, bool send_update);
  void signal_write_event(bool call_update);
  void reenable(VIO *vio) override;
  virtual void transaction_done() override;
  virtual bool
  ignore_keep_alive() override
  {
    // The stream should always close.  The session will stick around until the appropriate GOAWAY frames are sent
    // In the Http/1 case, we must watch the keep alive header to keep the session around appropriately
    return true;
  }

  void restart_sending();
  void send_body(bool call_update);
  void push_promise(URL &url, const MIMEField *accept_encoding);

  // Stream level window size
  ssize_t client_rwnd;
  ssize_t server_rwnd = Http2::initial_window_size;

  uint8_t *header_blocks        = nullptr;
  uint32_t header_blocks_length = 0;  // total length of header blocks (not include
                                      // Padding or other fields)
  uint32_t recv_header_length = 0; // total length of payload (include Padding
                                      // and other fields)
  bool recv_end_stream = false;
  bool send_end_stream = false;

  bool parsing_header_done      = false;
  bool is_first_transaction_flag = false;

  MIOBuffer recv_buffer                 = CLIENT_CONNECTION_FIRST_READ_BUFFER_SIZE_INDEX; // Buffer to gather bytes read from peer
  MIOBuffer recv_trailer_buffer         = CLIENT_CONNECTION_FIRST_READ_BUFFER_SIZE_INDEX; // Buffer to gather bytes read from peer
  Http2DependencyTree::Node *priority_node = nullptr;


  HTTPHdr *
  get_send_header()
  {
    return &_send_header;
  }

  EThread *
  get_thread()
  {
    return _thread;
  }

  IOBufferReader *send_get_data_reader() const;
  IOBufferReader *recv_get_data_reader() const;

  bool
  is_send_chunked() const
  {
    return chunked_send;
  }
  bool
  is_recv_chunked() const
  {
    return chunked_recv;
  }

  void release(IOBufferReader *r) override;

  virtual bool
  allow_half_open() const override
  {
    return false;
  }

  virtual void set_active_timeout(ink_hrtime timeout_in) override;
  virtual void set_inactivity_timeout(ink_hrtime timeout_in) override;
  virtual void cancel_inactivity_timeout() override;
  void clear_inactive_timer();
  void clear_active_timer();
  void clear_timers();
  void clear_io_events();
  bool
  is_state_writeable() const
  {
    return _state == Http2StreamState::HTTP2_STREAM_STATE_OPEN ||
           _state == Http2StreamState::HTTP2_STREAM_STATE_HALF_CLOSED_REMOTE ||
           _state == Http2StreamState::HTTP2_STREAM_STATE_RESERVED_LOCAL ||
           (initiating_flag && _state == Http2StreamState::HTTP2_STREAM_STATE_IDLE);
  }

  bool
  is_closed() const
  {
    return closed;
  }

  bool
  is_first_transaction() const override
  {
    return is_first_transaction_flag;
  }

  bool
  is_initiating_connection() const
  {
    return initiating_flag;
  }

  void
  set_initiating_connection()
  {
    initiating_flag = true;
  }

  void recv_process_data(IOBufferReader *dechunked_reader, int max_read_len);
  void recv_process_trailer();
private:
  void send_initialize_data_handling(bool &is_done);
  void recv_initialize_data_handling(bool &is_done);
  void send_process_data(bool &is_done);
  bool send_is_data_available() const;
  bool recv_is_data_available() const;
  Event *send_tracked_event(Event *event, int send_event, VIO *vio);

  HTTPParser http_parser; // Header parsing engine
  ink_hrtime _start_time = 0;
  EThread *_thread       = nullptr;
  Http2StreamId _id;
  Http2StreamState _state = Http2StreamState::HTTP2_STREAM_STATE_IDLE;

  HTTPHdr _recv_header; // Structure to process the headers received from peer
  HTTPHdr _send_header; // Structure to stage headers to send to peer
  VIO read_vio;
  VIO write_vio;
  IOBufferReader *send_reader          = nullptr;
  IOBufferReader *recv_reader           = nullptr;
  int first_trailer_slot = 0;

  bool trailing_header = false;
  bool body_done       = false;
  bool chunked_send    = false; // True if the data we are sending is chunked
  bool chunked_recv    = false; // True if the data we are receiving is chunked
  bool initiating_flag = false; // True if the stream sends the request

  // A brief disucssion of similar flags and state variables:  _state, closed, terminate_stream
  //
  // _state tracks the HTTP2 state of the stream.  This field completely coincides with the H2 spec.
  //
  // closed is a flag that gets set when the framework indicates that the stream should be shutdown.  This flag
  // is set from either do_io_close, which indicates that the HttpSM is starting the close, or initiating_close,
  // which indicates that the HTTP2 infrastructure is starting the close (e.g. due to the HTTP2 session shuttig down
  // or a end of stream frame being received.  The closed flag does not indicate that it is safe to delete the stream
  // immediately. Perhaps the closed flag could be folded into the _state field.
  //
  // terminate_stream flag gets set from the transaction_done() method.  This means that the HttpSM has shutdown.  Now
  // we can delete the stream object.  To ensure that the session and transaction close hooks are executed in the correct order
  // we need to enforce that the stream is not deleted until after the state machine has shutdown.  The reentrancy_count is
  // associated with the terminate_stream flag.  We need to make sure that we don't delete the stream object while we have stream
  // methods on the stack.  The reentrancy count is incremented as we enter the stream event handler.  As we leave the event
  // handler we decrement the reentrancy count, and check to see if the teriminate_stream flag and destroy the object if that is the
  // case.
  // The same pattern is used with HttpSM for object clean up.
  //
  bool closed           = false;
  int reentrancy_count  = 0;
  bool terminate_stream = false;

  uint64_t data_length = 0;
  uint64_t bytes_sent  = 0;
  int offset_to_chunked = 0;

  ChunkedHandler chunked_handler;
  Event *cross_thread_event      = nullptr;
  Event *buffer_full_write_event = nullptr;

  // Support stream-specific timeouts
  ink_hrtime active_timeout = 0;
  Event *active_event       = nullptr;

  ink_hrtime inactive_timeout    = 0;
  ink_hrtime inactive_timeout_at = 0;
  Event *inactive_event          = nullptr;

  Event *read_event  = nullptr;
  Event *write_event = nullptr;
};

extern ClassAllocator<Http2Stream> http2StreamAllocator;

extern bool check_continuation(Continuation *cont);
extern bool check_stream_thread(Continuation *cont);

#endif
