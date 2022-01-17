/** @file

  An example program that does a null transform of response body content.

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

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

#include "ts/ts.h"
#include "tee_info.h"

#define PLUGIN_NAME "tee_decrypt"

int data_arg_index = -1;

class MyData
{
public:
  MyData(TSHttpTxn txnp)
  {
    this->resp_output_buffer = TSIOBufferCreate();
    this->req_output_buffer  = TSIOBufferCreate();
    this->resp_output_reader = TSIOBufferReaderAlloc(this->resp_output_buffer);
    this->req_output_reader  = TSIOBufferReaderAlloc(this->req_output_buffer);
    this->txnp               = txnp;
  }
  ~MyData()
  {
    TSDebug(PLUGIN_NAME, "Delete MyData");
    if (this->req_output_buffer) {
      TSIOBufferDestroy(this->req_output_buffer);
    }
    if (this->resp_output_buffer) {
      TSIOBufferDestroy(this->resp_output_buffer);
    }
    if (this->tee_info) {
      delete tee_info;
    }
  }
  TSVIO resp_output_vio               = nullptr;
  TSVIO req_output_vio                = nullptr;
  TSIOBuffer req_output_buffer        = nullptr;
  TSIOBufferReader req_output_reader  = nullptr;
  TSIOBuffer resp_output_buffer       = nullptr;
  TSIOBufferReader resp_output_reader = nullptr;
  TSHttpTxn txnp;
  TeeInfo *tee_info = nullptr;
};

class ContData
{
public:
  ContData(MyData *mydata) : data(mydata) {}
  ~ContData() { TSDebug(PLUGIN_NAME, "~ContData forward=%d", this->forward); }
  MyData *data = nullptr;
  bool forward = true;
};

static void
send_request_header(TSHttpTxn txnp)
{
  MyData *data = static_cast<MyData *>(TSUserArgGet(txnp, data_arg_index));
  TSMBuffer creq_buff;
  TSMLoc creq_loc;
  if (TS_SUCCESS != TSHttpTxnClientReqGet(txnp, &creq_buff, &creq_loc)) {
    fprintf(stderr, "Failed to get client request");
    return;
  }
  data->tee_info->send_header(creq_buff, creq_loc, true);
  TSHandleMLocRelease(creq_buff, TS_NULL_MLOC, creq_loc);
}

static void
send_response_header(TSHttpTxn txnp)
{
  MyData *data = static_cast<MyData *>(TSUserArgGet(txnp, data_arg_index));
  TSMBuffer sresp_buff;
  TSMLoc sresp_loc;
  if (TS_SUCCESS != TSHttpTxnServerRespGet(txnp, &sresp_buff, &sresp_loc)) {
    fprintf(stderr, "Failed to get server response");
    return;
  }
  data->tee_info->send_header(sresp_buff, sresp_loc, false);
  TSHandleMLocRelease(sresp_buff, TS_NULL_MLOC, sresp_loc);
}

static void
populate_tee_info(MyData *data)
{
  if (data->tee_info == nullptr) {
    // Deferred setting up the tee_info until we knew the destination address
    sockaddr const *src_addr = TSHttpTxnIncomingAddrGet(data->txnp);
    sockaddr const *dst_addr = TSHttpTxnOutgoingAddrGet(data->txnp);
    data->tee_info           = new TeeInfo{src_addr, dst_addr};
    // Go ahead and send the handshake and the request header
    data->tee_info->send_handshake();
    send_request_header(data->txnp);
  }
}

static void
check_txn_data(TSHttpTxn txnp)
{
  MyData *data = static_cast<MyData *>(TSUserArgGet(txnp, data_arg_index));
  populate_tee_info(data);
}

ContData *
get_cont_data(TSCont contp)
{
  ContData *conn_data = static_cast<ContData *>(TSContDataGet(contp));
  populate_tee_info(conn_data->data);
  return conn_data;
}

static void
handle_transform(TSCont contp)
{
  TSVConn output_conn;
  TSVIO input_vio;
  ContData *conn_data;
  int64_t towrite;

  TSDebug(PLUGIN_NAME, "Entering handle_transform()");
  /* Get the output (downstream) vconnection where we'll write data to. */

  output_conn = TSTransformOutputVConnGet(contp);

  /* Get the write VIO for the write operation that was performed on
   * ourself. This VIO contains the buffer that we are to read from
   * as well as the continuation we are to call when the buffer is
   * empty. This is the input VIO (the write VIO for the upstream
   * vconnection).
   */
  input_vio = TSVConnWriteVIOGet(contp);

  /* Get our data structure for this operation. The private data
   * structure contains the output VIO and output buffer. If the
   * private data structure pointer is NULL, then we'll create it
   * and initialize its internals.
   */
  TSVIO output_vio;
  conn_data = get_cont_data(contp);
  if (conn_data->forward) {
    if (conn_data->data->req_output_vio == nullptr && output_conn != nullptr) {
      conn_data->data->req_output_vio = TSVConnWrite(output_conn, contp, conn_data->data->req_output_reader, INT64_MAX);
    }
    output_vio = conn_data->data->req_output_vio;
  } else if (!conn_data->forward) {
    if (conn_data->data->resp_output_vio == nullptr && output_conn != nullptr) {
      conn_data->data->resp_output_vio = TSVConnWrite(output_conn, contp, conn_data->data->resp_output_reader, INT64_MAX);
    }
    output_vio = conn_data->data->resp_output_vio;
  }

  /* Determine how much data we have left to read. For this null
   * transform plugin this is also the amount of data we have left
   * to write to the output connection.
   */
  towrite = TSVIONTodoGet(input_vio);
  TSDebug(PLUGIN_NAME, "\ttoWrite is %" PRId64 "", towrite);

  if (towrite > 0) {
    /* The amount of data left to read needs to be truncated by
     * the amount of data actually in the read buffer.
     */
    int64_t avail = TSIOBufferReaderAvail(TSVIOReaderGet(input_vio));
    TSDebug(PLUGIN_NAME, "\tavail is %" PRId64 "", avail);
    if (towrite > avail) {
      towrite = avail;
    }

    if (towrite > 0) {
      /* Copy the data from the read buffer to the output buffer. */
      TSIOBufferCopy(TSVIOBufferGet(output_vio), TSVIOReaderGet(input_vio), towrite, 0);

      /* Tee the packets to the side for analysis */
      conn_data->data->tee_info->send_data(TSVIOReaderGet(input_vio), conn_data->forward);

      /* Tell the read buffer that we have read the data and are no
       * longer interested in it.
       */
      TSIOBufferReaderConsume(TSVIOReaderGet(input_vio), towrite);

      /* Modify the input VIO to reflect how much data we've
       * completed.
       */
      TSVIONDoneSet(input_vio, TSVIONDoneGet(input_vio) + towrite);
    }
  }

  /* Now we check the input VIO to see if there is data left to
   * read.
   */
  if (TSVIONTodoGet(input_vio) > 0) {
    if (towrite > 0) {
      /* If there is data left to read, then we reenable the output
       * connection by reenabling the output VIO. This will wake up
       * the output connection and allow it to consume data from the
       * output buffer.
       */
      TSVIOReenable(output_vio);

      /* Call back the input VIO continuation to let it know that we
       * are ready for more data.
       */
      TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_READY, input_vio);
    }
  } else {
    /* If there is no data left to read, then we modify the output
     * VIO to reflect how much data the output connection should
     * expect. This allows the output connection to know when it
     * is done reading. We then reenable the output connection so
     * that it can consume the data we just gave it.
     */
    TSVIONBytesSet(output_vio, TSVIONDoneGet(input_vio));

    if (TSVConnClosedGet(contp)) {
      TSDebug(PLUGIN_NAME, "\tVConn is closed");
      delete conn_data;
      TSContDestroy(contp);
    } else if (towrite > 0) {
      /* Call back the input VIO continuation to let it know that we
       * have completed the write operation.
       */
      TSVIOReenable(output_vio);
      TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_COMPLETE, input_vio);
    }
  }
}

static int
null_transform(TSCont contp, TSEvent event, void *edata)
{
  /* Check to see if the transformation has been closed by a call to
   * TSVConnClose.
   */
  TSDebug(PLUGIN_NAME, "Entering null_transform() event=%d", event);

  if (TSVConnClosedGet(contp)) {
    TSDebug(PLUGIN_NAME, "\tVConn is closed");
    ContData *conn_data = (ContData *)TSContDataGet(contp);
    if (conn_data) {
      delete conn_data;
    }
    TSContDestroy(contp);
    return 0;
  } else {
    switch (event) {
    case TS_EVENT_ERROR: {
      TSVIO input_vio;

      TSDebug(PLUGIN_NAME, "\tEvent is TS_EVENT_ERROR");
      /* Get the write VIO for the write operation that was
       * performed on ourself. This VIO contains the continuation of
       * our parent transformation. This is the input VIO.
       */
      input_vio = TSVConnWriteVIOGet(contp);

      /* Call back the write VIO continuation to let it know that we
       * have completed the write operation.
       */
      TSContCall(TSVIOContGet(input_vio), TS_EVENT_ERROR, input_vio);
    } break;
    case TS_EVENT_VCONN_WRITE_COMPLETE:
      TSDebug(PLUGIN_NAME, "\tEvent is TS_EVENT_VCONN_WRITE_COMPLETE");
      /* When our output connection says that it has finished
       * reading all the data we've written to it then we should
       * shutdown the write portion of its connection to
       * indicate that we don't want to hear about it anymore.
       */
      TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
      break;

    /* If we get a WRITE_READY event or any other type of
     * event (sent, perhaps, because we were re-enabled) then
     * we'll attempt to transform more data.
     */
    case TS_EVENT_VCONN_WRITE_READY:
      TSDebug(PLUGIN_NAME, "\tEvent is TS_EVENT_VCONN_WRITE_READY");
      handle_transform(contp);
      break;
    default:
      TSDebug(PLUGIN_NAME, "\t(event is %d)", event);
      handle_transform(contp);
      break;
    }
  }

  return 0;
}

static void
transform_add(TSHttpTxn txnp, TSCont orig_contp)
{
  TSVConn connp, rev_connp;

  TSDebug(PLUGIN_NAME, "Entering transform_add()");
  connp                   = TSTransformCreate(null_transform, txnp);
  rev_connp               = TSTransformCreate(null_transform, txnp);
  MyData *data            = new MyData{txnp};
  ContData *conn_data     = new ContData{data};
  ContData *rev_conn_data = new ContData{data};
  rev_conn_data->forward  = false;
  TSContDataSet(connp, conn_data);
  TSContDataSet(rev_connp, rev_conn_data);
  TSUserArgSet(txnp, data_arg_index, data);
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, rev_connp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_REQUEST_TRANSFORM_HOOK, connp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, orig_contp);
}

static int
transform_plugin(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = (TSHttpTxn)edata;

  TSDebug(PLUGIN_NAME, "Entering transform_plugin()");
  switch (event) {
  case TS_EVENT_HTTP_TXN_CLOSE: {
    // Clean things up.
    TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);
    MyData *data   = static_cast<MyData *>(TSUserArgGet(txnp, data_arg_index));
    if (data) {
      delete data;
    }
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  }
  case TS_EVENT_HTTP_READ_REQUEST_HDR:
    TSDebug(PLUGIN_NAME, "\tEvent is TS_EVENT_HTTP_READ_REQUEST_HDR");
    transform_add(txnp, contp);

    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    TSDebug(PLUGIN_NAME, "\tEvent is TS_EVENT_HTTP_READ_RESPONSE_HDR");
    check_txn_data(txnp);
    send_response_header(txnp);
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  default:
    TSDebug(PLUGIN_NAME, "\tOther Event %d", event);
    break;
  }

  return 0;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Aviatrix";
  info.support_email = "dev@trafficserver.apache.org";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] Plugin registration failed", PLUGIN_NAME);

  } else {
    if (argc < 3) {
      TSError("[%s] Plugin failed. Requires arguments <src_gre_address> and <dst_gre_address>", PLUGIN_NAME);
      return;
    }
    TSCont contp = TSContCreate(transform_plugin, NULL);
    TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, contp);
    TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
    TSUserArgIndexReserve(TS_USER_ARGS_TXN, "tee_data", "", &data_arg_index);
    gre_info.init(argv, argc); // Initialize some data structures
  }
  return;
}
