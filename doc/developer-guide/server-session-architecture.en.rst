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

.. _client-session-architecture:

A Proposal for Server Client and Transaction Generalization
***********************************************************

Currently ATS only supports HTTP/1.x to the origin.  There is a need to additionally support HTTP/2 and likely other protocols in the future. 
To support that change, we propose generalizing the current Server Session class structure in a similar way the Client Session classes
were generalized.

.. figure:: /static/images/sessions/current_server_objects.png
   :align: center
   :alt: Current server objects

This figure above shows the objects involved in the current ATS implement when communicating to the origin.
The HttpServerSession object refers to a NetVC (either UnixNetVConnection or SSLNetVConnection) which takes care of the communication
to the origin.  The HttpSM object refers to the HttpServerSession object via the server_session member variable.

ATS attempts to reuse connections.  When it needs to communicate to the origin, the HttpSM first makes calls against HttpSessionManager.
HttpSessionManager contains one or more pools of previously established HttpServerSession objects in hash tables keyed by IP address 
and/or hostname.  If the HttpSessionManager finds a matching HttpSessionServer, it removes the object from the appropriate
HttpSessionManager pool and returns it to the HttpSM.  If no maching server object was found, the HttpSM will initiate a new connection
and store the resulting NetVC in a new HttpServerSession object.

When the transaction associated with the HttpSM is finished, the HttpSM attempts to deliver the HttpServerSession object back to the
HttpSessionManager so it is avaliable for future HttpSM's.  


Proposed Classes
================

ProxyServerSession
------------------

.. figure:: /static/images/sessions/server_session_hierarchy.png
   :align: center
   :alt: ProxyServerSession hierarchy

The ProxyServerSession class abstracts the key features of a server session.  It contains zero or more ProxyServerTransaction objects.  It also has a reference to the associated NetVC (either UnixNetVConnection or SSLNetVConnection).  The session class is responsible for interfacing with the origin server protocol.

At this point there will be two concrete subclasses: Http1ServerSession and Http2ServerSession.  The Http1ServerSession
only has at most one transaction active at a time.  The HTTP/2 protocol allows for multiple simultaneous active 
transactions.  

The HttpSessionManager will store pools of ProxyServerSession objects instead of HttpServerSession.  Since HTTP/2 supports multiple simultaneous active transactions, the Http2ServerSession does not have to be removed from the HttpServerSession pool while a child transaction object is in use.

ProxyServerTransaction
----------------------

.. figure:: /static/images/sessions/server_transaction_hierarchy.png
   :align: center
   :alt: ProxyServerTransaction hierarchy

The ProxyServerTransaction class abstracts the key features of a server transaction.  It has a reference to its
parent ProxyServerSession.  The HttpSM will reference at most one ProxyServerTransaction via the server_session member variable.

There will be two concrete subclasses: Http1ServerTransaction and Http2ServerStream.

The bulk of the logic in the current HttpServerSession will be split between Http1ServerSession and Http1ServerTransaction.

Presumably the Http2ServerSession and Http2ServerStream will be able to leverage much of the existing Http2ConnectionState and HTTP2 classes.

Server Session Object Relationships
===================================

HTTP/1.x Server Objects
-----------------------

.. figure:: /static/images/sessions/http1_server_objects.png
   :align: center
   :alt: HTTP/1.x server session objects

This diagram shows the relationships between objects created as part of a HTTP/1.x server session.  A NetVC 
object performs the basic network level protocols.  The Http1ServerSession object has a reference to the 
associated NetVC object.  The NetVC object is available via the :code:`ProxyServerSession::get_netvc()` method.

The Http1ServerSession object contains a Http1ServerTransaction object.

The Http1ServerTransaction object is associated with the HttpSM object :code:`HttpSM::attach_server_session()`.

HTTP/2 Server Objects
---------------------

.. figure:: /static/images/sessions/http2_server_objects.png
   :align: center
   :alt: HTTP/2 server session objects

This diagram shows the relationships between objects created as part of a HTTP/2 server session.  It is very similar
to the HTTP/1.x case.  The Http2ServerSession object interacts with the NetVC.  The Http2ServerStream object is associated
with the HttpSM via the :code:`HttpSM::attach_server_session()` call.

One difference is that the HTTP/2 protocol allows for multiple simultaneous transactions, so the Http2ServerSession
object must be able to manage multiple streams. From the HttpSM perspective it is interacting with a 
ProxyServerTransaction object, and there is no difference between working with a Http2ServerStream and a Http1ServerTransaction.


Open Issues
===========

HTTP/2 additions
----------------

HTTP/2 communication to origin should be able to leverage a lot of the logic in the proxy/http2 area, but presumable we are missing some client-oriented logic.

Sticky servers
--------------

The current ATS implementation binds the HttpServerSession to the ProxyClientServer session.  The next
time the transaction comes through session, it will attempt to reuse that HttpServerSession if the 
setting proxy.config.http.attach_server_session_to_client is set to 1 and the hostname and/or IP address matches. 

We will need to think carefully on the impact of this "stickiness" on the Http2ServerSessions.

Limiting HTTP/2 Session Reuse
-----------------------------

Since HTTP/2 allows for multiple simultaneous streams, we don't remove the Http2ServerSession object from the HttpSessionManager.  All
the requests for a particular origin with a single Http2ServerSession would create streams on the same sessions.  At a minimum the reuse logic should follow the maximum concurrent stream limits.  Perhaps additional settings will be needed.
