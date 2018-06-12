/** @file

  singleton.h - a containuer of connection objects

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

#ifndef _SINGLETON_H_
#define _SINGLETON_H_

/* Original version Copyright (C) Scott Bilas, 2000.
 * All rights reserved worldwide.
 *
 * This software is provided "as is" without express or implied
 * warranties. You may freely copy and compile this source into
 * applications you distribute provided that the copyright text
 * below is included in the resulting source code, for example:
 * "Portions Copyright (C) Scott Bilas, 2000"
 */

#include <new>
template <typename _T> class Singleton
{
protected:
  static _T *ms_Singleton;
  Singleton() {}

public:
  ~Singleton(void)
  {
    if (ms_Singleton)
      delete ms_Singleton;
  }

  static _T &
  getSingleton(void)
  {
    if (!ms_Singleton) {
      ms_Singleton = new (std::nothrow) _T();
    }

    return (*ms_Singleton);
  }

  static _T *
  getSingletonPtr(void)
  {
    if (!ms_Singleton) {
      ms_Singleton = new (std::nothrow) _T();
    }

    return (ms_Singleton);
  }
};

#endif
