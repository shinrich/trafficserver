#include <cstdlib>
#include <stdio.h>
#include <cstdio>
#include <strings.h>
#include <sstream>
#include <cstring>
#include <getopt.h>

#include "ts/ts.h"
#include "ts/ink_error.h"
#include "ts/ink_defs.h"

using namespace std;

#define DEBUG_TAG_LOG_HEADERS "xdebug.headers"

///////////////////////////////////////////////////////////////////////////
// Dump a header on stderr, useful together with TSDebug().
void
print_headers(TSHttpTxn txn, TSMBuffer bufp, TSMLoc hdr_loc, std::stringstream &ss)
{
  TSIOBuffer output_buffer;
  TSIOBufferReader reader;
  TSIOBufferBlock block;
  const char *block_start;
  int64_t block_avail;

  output_buffer = TSIOBufferCreate();
  reader        = TSIOBufferReaderAlloc(output_buffer);

  /* This will print just MIMEFields and not the http request line */
  TSMimeHdrPrint(bufp, hdr_loc, output_buffer);

  /* We need to loop over all the buffer blocks, there can be more than 1 */
  block = TSIOBufferReaderStart(reader);
  do {
    block_start = TSIOBufferBlockReadStart(block, reader, &block_avail);
    if (block_avail > 0) {
      ss << std::string(block_start, static_cast<int>(block_avail)) << endl;
    }
    TSIOBufferReaderConsume(reader, block_avail);
    block = TSIOBufferReaderStart(reader);
  } while (block && block_avail != 0);

  /* Free up the TSIOBuffer that we used to print out the header */
  TSIOBufferReaderFree(reader);
  TSIOBufferDestroy(output_buffer);

  TSDebug(DEBUG_TAG_LOG_HEADERS, "%s", ss.str().c_str());
}

void
log_headers(TSHttpTxn txn, TSMBuffer bufp, TSMLoc hdr_loc, char const *type_msg)
{
  if (TSIsDebugTagSet(DEBUG_TAG_LOG_HEADERS)) {
    std::stringstream output;
    print_headers(txn, bufp, hdr_loc, output);
    TSDebug(DEBUG_TAG_LOG_HEADERS, "\n=============\n %s headers are... \n %s", type_msg, output.str().c_str());
  }
}

void
print_request_headers(TSHttpTxn txn, std::stringstream &output)
{
  TSMBuffer buf_c, buf_s;
  TSMLoc hdr_loc;

  output << "<RequestHeaders>\n";
  if (TSHttpTxnClientReqGet(txn, &buf_c, &hdr_loc) == TS_SUCCESS) {
    output << "<Client>\n";
    print_headers(txn, buf_c, hdr_loc, output);
    output << "</Client>\n";
    TSHandleMLocRelease(buf_c, TS_NULL_MLOC, hdr_loc);
  }
  if (TSHttpTxnServerReqGet(txn, &buf_s, &hdr_loc) == TS_SUCCESS) {
    output << "<Server>\n";
    print_headers(txn, buf_s, hdr_loc, output);
    output << "</Server>\n";
    TSHandleMLocRelease(buf_s, TS_NULL_MLOC, hdr_loc);
  }
  output << "</RequestHeaders>\n";
}

void
print_response_headers(TSHttpTxn txn, std::stringstream &output)
{
  TSMBuffer buf_c, buf_s;
  TSMLoc hdr_loc;

  output << "<ResponseHeaders>\n";
  if (TSHttpTxnServerRespGet(txn, &buf_s, &hdr_loc) == TS_SUCCESS) {
    output << "<Server>\n";
    print_headers(txn, buf_s, hdr_loc, output);
    output << "</Server>\n";
    TSHandleMLocRelease(buf_s, TS_NULL_MLOC, hdr_loc);
  }
  if (TSHttpTxnClientRespGet(txn, &buf_c, &hdr_loc) == TS_SUCCESS) {
    output << "<Client>\n";
    print_headers(txn, buf_c, hdr_loc, output);
    output << "</Client>\n";
    TSHandleMLocRelease(buf_c, TS_NULL_MLOC, hdr_loc);
  }
  output << "</ResponseHeaders>\n";
}
