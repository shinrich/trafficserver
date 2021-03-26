/** @file

  ALPNSupport.cc provides implmentations for ALPNSupport methods

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

#include "P_ALPNSupport.h"
#include "P_SSLNextProtocolSet.h"
#include "records/I_RecHttp.h"

void
ALPNSupport::clear()
{
  if (npn) {
    ats_free(npn);
    npn   = nullptr;
    npnsz = 0;
  }
  npnSet      = nullptr;
  npnEndpoint = nullptr;
}

bool
ALPNSupport::setSelectedProtocol(const unsigned char *proto, unsigned int len)
{
  // If there's no NPN set, we should not have done this negotiation.
  ink_assert(this->npnSet != nullptr);

  this->npnEndpoint = this->npnSet->findEndpoint(proto, static_cast<unsigned>(len));
  this->npnSet      = nullptr;

  if (this->npnEndpoint == nullptr) {
    Error("failed to find registered SSL endpoint for '%.*s'", len, proto);
    return false;
  }
  return true;
}

void
ALPNSupport::disableProtocol(int idx)
{
  this->protoenabled.markOut(idx);
  // Update the npn string
  if (npnSet) {
    npnSet->create_npn_advertisement(protoenabled, &npn, &npnsz);
  }
}

void
ALPNSupport::enableProtocol(int idx)
{
  this->protoenabled.markIn(idx);
  // Update the npn string
  if (npnSet) {
    npnSet->create_npn_advertisement(protoenabled, &npn, &npnsz);
  }
}

void
ALPNSupport::registerNextProtocolSet(SSLNextProtocolSet *s, const SessionProtocolSet &protos)
{
  this->protoenabled = protos;
  this->npnSet       = s;
  npnSet->create_npn_advertisement(protoenabled, &npn, &npnsz);
}

bool
ALPNSupport::process_alpn_protocols(const std::string_view protocols, unsigned char *client_alpn_protocols, int &alpn_array_len)
{
  // Count up the number of separators
  int start     = 0;
  size_t offset = protocols.find(',', start);
  int index     = 0;
  bool retval   = true;
  while (offset != protocols.npos) {
    if ((index + 1 + static_cast<int>(offset) - start) > alpn_array_len) {
      retval = false;
      break;
    }
    client_alpn_protocols[index++] = offset - start;
    memcpy(client_alpn_protocols + index, protocols.data() + start, offset - start);
    index += offset - start;
    start  = offset + 1;
    offset = protocols.find(',', start);
  }
  // Copy in the last string
  offset = protocols.length();
  if ((index + 1 + static_cast<int>(offset) - start) > alpn_array_len) {
    retval         = false;
    alpn_array_len = 0;
  } else {
    client_alpn_protocols[index++] = offset - start;
    memcpy(client_alpn_protocols + index, protocols.data() + start, offset - start);
    index += offset - start;
    alpn_array_len = index;
  }
  return retval;
}
