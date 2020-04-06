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

.. include:: ../../../common.defs
.. default-domain:: c

TSSecretID
**********

Synopsis
========

.. code-block:: cpp

    #include <ts/apidefs.h>

.. type:: TSSecretID

   .. member:: const char * name
      
   .. member:: int version

Description
===========

:type:`TSSecretID` stores the name and version (if applicable) of the secret.  A pointer to a :type:`TSSecretID` instance is passed in the
data parameter when the :cpp:enumerator:`TSLifecycleHookID::TS_LIFECYCLE_SSL_SECRET_HOOK` callback is triggered.  The plugin uses the `name` member to look up the secret. When retreiving
certificate and private key secrets, |TS| will pass in the version of the retrieved certificate for looking up the private key.


