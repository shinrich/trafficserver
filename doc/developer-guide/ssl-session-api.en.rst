.. Licensed to the Apache Software Foundation (ASF) under one
   or more contributor license agreements.  See the NOTICE file
   distributed with this work for additional information
   regarding copyright ownership.  The ASF licenses this file
   to you under the Apache License, Version 2.0 (the
   "License"); you may not use this file except in compliance
   with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.

.. include:: ../common.defs

.. _ssl-session-api:

TLS Session Plugin API
**********************

These interfaces enable a plugin to hook into operations on the session cache.  It also 
enables the plugin to update the session cache based on outside information, e.g. peer servers.

TS_SSL_SESSION_HOOK
-------------------

This hook is invoked when a change has been made to the ATS session cache or a session has been accessed
from ATS via openssl.  These hooks are only activated if the ATS implementation of the session cache is in
use.  This means that the setting proxy.config.ssl.session_cache has been set to 2.

The hook callback has the following signature

.. function:: int SSL_session_callback(TSCont contp, TSEvent event, void * edata)

The edata parameter is a pointer to a TSSslSessionId.

This callback in synchronous since the underlying openssl callback is unable to pause processing.

The following events can be sent to this callback

* TS_EVENT_SSL_SESSION_NEW - Sent after a new session has been inserted into the SSL session cache.  The 
plugin can call TSSslSessionGet() to retrieve the actual session object.  The plugin could communicate information
about the new session to other processes or update additional logging or statistics.
* TS_EVENT_SSL_SESSION_GET - Sent after a session has been fetched from the SSL session cache by a client request.
The plugin could update additional logginc and statistics.
* TS_EVENT_SSL_SESSION_REMOVE - Sent after a session has been removed from the SSL session cache.  The plugin
could communication information about the session removal to other processes or update additional logging and statistics.

Types
*****

TSSslSessionID
--------------

This object represents the SSL session ID as a buffer and length.  The TS_SSL_MAX_SSL_SESSION_ID_LENGTH is the same value
as the openssl constant SSL_MAX_SSL_SESSION_ID_LENGTH. The plugin has direct access to this object since creating and 
manipulating session IDs seems like a fairly common operation (rather than providing an API to access the data via an 
opaque TS object type).

typedef struct TSSslSessionID_s {
  char bytes[TS_SSL_MAX_SSL_SESSION_ID_LENGTH];
  size_t len;
} TSSslSessionID;

TSSslSession
------------

The SSL session object.  It can be cast to the openssl type SSL_SESSION *.

Utility Functions
*****************

These functions perform the appropriate logging on the session cache to avoid errors.

.. function:: TSSslSession TSSslSessionGet(const TSSslSessionID *sessionid) 

Returns the SSL session object stored in SSL session cache that corresponds to the sessionid parameter.  If there is no
match, it returns NULL.

.. function:: int TSSslSessionGetBuffer(const TSSslSessionID *sessionid, char *buffer, int *len_ptr)

Returns the information about the SSL session object that corresponds to the sessionid parameter in the buffer parameter.
Passing around openssl serialized session information can be quite useful.  When the function is called len_ptr should point to the amount of space
available in the buffer parameter.  The function returns the amount of data really needed to encode the session.  0 is returned if the session
cannot be serialized.  len_ptr is updated with the amount of data actually stored in the buffer.

.. function:: TSReturnCode TSSslSessionInsert(const TSSslSessionID *sessionid, TSSslSession addSession)

This function inserts the session specified by the addSession parameter into the SSL session cache under the sessionid key.  If there is already
an entry in the cache for the session id key, it is first removed before the new entry is added.

.. function:: TSReturnCode TSSslSessionRemove(const TSSslSessionID *sessionid)

This function removes the session entry from the session cache that is keyed by sessionid.

.. function:: void TSSslTicketKeyUpdate(char *ticketData, int ticketDataLength)

This function updates the running ATS process to use a new set of Session Ticket Encryption keys.  This behaves the same way as 
updating the session ticket encrypt key file with new data and reloading the current ATS process.  However, this API does not
require writing session ticket encryption keys to disk.  

Note: What happens is both files are specified and this API is used?  On configuration reload while the files replace what was 
last set by this API?

Example Use Case
****************

Consider deploying a set of ATS servers as a farm behind a layer 4 load balancer.  The load balancer does not 
guaratee that all the requests from a single client are directed to the same ATS box.  Therefore to maximize TLS session
reuse, the servers should share session state via some external communication library like redis or rabbitmq.

To do this, they write a plugin that sets the TS_SSL_SESSION_HOOK.  When the hook is triggered, the plugin function sends the 
updated session state to the other ATS servers via the communication library.

The plugin also has thread that listents for updates and calls TSSslSessionInsert and TSSslSessionRemove to update the local session cache accordingly.

The plugin can also engage in a protocol to periodically update the session ticket encryption key and communicate the new key to its
peers.  The plugin calls TSSslSessionTicketKeyUpdate to update the local ATS process with the newest keys and the last N keys.

