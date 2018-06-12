/** @file

  simple_pool.cc - a containuer of connection objects

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

#include "simple_pool.h"
#include "scope_lock.h"

connection *
simple_pool::get()
{
  connection *ret = NULL;

  {
    scope_lock sl(&access_mutex);
    for (std::set<connection *>::iterator it = connections.begin(); it != connections.end();) {
      if (*it) {
        if ((*it)->is_valid()) {
          ret = *it;
          connections.erase(it++);
          break;
        } else {
          delete *it;
          connections.erase(it++);
        }
      }
    }
  }

  if (ret == NULL) {
    ret = connection::create(_host, _port, _timeout);
    if (ret && !ret->is_valid()) {
      delete ret;
      ret = NULL;
    }
  }

  return ret;
}

void
simple_pool::put(connection *conn)
{
  if (conn == NULL)
    return;

  if (!conn->is_valid()) {
    delete conn;
    return;
  }

  {
    scope_lock sl(&access_mutex);
    connections.insert(conn);
  }
}

simple_pool::simple_pool(const std::string &host, unsigned int port, unsigned int timeout)
  : _host(host), _port(port), _timeout(timeout)
{
  pthread_mutex_init(&access_mutex, NULL);
}
