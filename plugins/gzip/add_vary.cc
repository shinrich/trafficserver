/** @file

  Implementation file for add_vary.h

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

#include <cstring>

#include <ts/ts.h>

#include "add_vary.h"
#include "debug_macros.h"

namespace
{

int
addVaryContFunc(TSCont contp, TSEvent event, void *eventData)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(eventData);

  switch (event) {
  case TS_EVENT_HTTP_SEND_RESPONSE_HDR: {
    info("adding \"Vary:\" header to client response (if not already present)");

    TSMBuffer bufp;
    TSMLoc client_resp;

    if (TSHttpTxnClientRespGet(txnp, &bufp, &client_resp) != TS_SUCCESS) {
      error("Could not access client response header");

    } else {
      Compress::addVaryHdr(bufp, client_resp);
    }
  }
  break;

  default: {
    error("Unexpected event for addVaryContFunc(): %d", static_cast<int>(event));
  }
  break;

  } // end switch

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);

  return 0;

} // end addVaryContFunc()

} // end anonymous namespace

namespace Compress
{

bool
addVaryHdr(TSMBuffer bufp, TSMLoc hdr)
{
  TSReturnCode ret;
  TSMLoc ce_loc;

  ce_loc = TSMimeHdrFieldFind(bufp, hdr, TS_MIME_FIELD_VARY, TS_MIME_LEN_VARY);
  if (ce_loc) {
    int idx, count, len;
    const char *value;

    count = TSMimeHdrFieldValuesCount(bufp, hdr, ce_loc);
    for (idx = 0; idx < count; idx++) {
      value = TSMimeHdrFieldValueStringGet(bufp, hdr, ce_loc, idx, &len);
      if (len && strncasecmp("Accept-Encoding", value, len) == 0) {
        // Vary: Accept-Encoding already present in header of response to client.
        count = 0;
        break;
      }
    }

    if (count > 0) {
      // Add Accept-Encoding to existing Vary header.
      ret = TSMimeHdrFieldValueStringInsert(bufp, hdr, ce_loc, -1, TS_MIME_FIELD_ACCEPT_ENCODING, TS_MIME_LEN_ACCEPT_ENCODING);

    } else {
      ret = TS_SUCCESS;
    }
    TSHandleMLocRelease(bufp, hdr, ce_loc);

  } else {
    if ((ret = TSMimeHdrFieldCreateNamed(bufp, hdr, TS_MIME_FIELD_VARY, TS_MIME_LEN_VARY, &ce_loc)) == TS_SUCCESS) {
      if ((ret = TSMimeHdrFieldValueStringInsert(bufp, hdr, ce_loc, -1, TS_MIME_FIELD_ACCEPT_ENCODING,
                                                 TS_MIME_LEN_ACCEPT_ENCODING)) == TS_SUCCESS) {
        ret = TSMimeHdrFieldAppend(bufp, hdr, ce_loc);
      }

      TSHandleMLocRelease(bufp, hdr, ce_loc);
    }
  }

  if (ret != TS_SUCCESS) {
    error("cannot add/update the Vary header");
    return false;
  }

  return true;

} // end addVaryHdr()

void
addVaryHdrContinuation(TSHttpTxn txnp)
{
  static TSCont contp = TSContCreate(addVaryContFunc, nullptr);

  TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp); // to add vary header as needed.
}

} // end namespace Compress
