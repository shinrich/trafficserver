/** @file

  scope_lock.h

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

#ifndef _SCOPE_LOCK_H
#define _SCOPE_LOCK_H

#include <pthread.h>

/**
 * @brief Scoped lock works by locking a mutex when they are constructed,
 * and unlocking it when they are destructed.
 * The C++ rules guarantee that when control flow leaves a scope (even via an exception),
 * objects local to the scope being exited are destructed correctly.
 */
class scope_lock
{
public:
  scope_lock(pthread_mutex_t *mutex) : m(mutex)
  {
    if (m) {
      pthread_mutex_lock(m);
    }
  }
  ~scope_lock()
  {
    if (m) {
      pthread_mutex_unlock(m);
    }
  }

private:
  pthread_mutex_t *m;
};

#endif
