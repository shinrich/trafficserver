/** @file

  A brief file description

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

/****************************************************************************

   PoolInterace.cc

   Description: Implementation of the PoolInterface class

 ****************************************************************************/
#include "PoolInterface.h"
#include "HttpSessionManager.h"

// void PoolInterface::release()
//
//   Releases the session for K-A reuse
//
void
PoolInterface::release()
{
  ProxySession *session = this->get_session();
  Debug("http_ss", "Releasing session, private_session=%d, sharing_match=%d", private_session, sharing_match);

  NetVConnection *netvc = session->get_netvc();
  netvc->control_flags.set_flags(0);

  // Private sessions are never released back to the shared pool
  if (private_session || TS_SERVER_SESSION_SHARING_MATCH_NONE == sharing_match) {
    session->do_io_close();
    return;
  }

  HSMresult_t r = httpSessionManager.release_session(this);

  if (r == HSM_RETRY) {
    // Session could not be put in the session manager
    //  due to lock contention
    // FIX:  should retry instead of closing
    // Make sure the vios for the current SM are cleared
    netvc->do_io_read(nullptr, 0, nullptr);
    netvc->do_io_write(nullptr, 0, nullptr);
    session->do_io_close();
  } else {
    session->set_shared();

    // The session was successfully put into the session
    //    manager and it will manage it
    // (Note: should never get HSM_NOT_FOUND here)
    ink_assert(r == HSM_DONE);
  }
}
