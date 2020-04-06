/** @file

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
#include <string>
#include <map>
#include "InkAPIInternal.h" // Added to include the ssl_hook and lifestyle_hook definitions
#include "tscore/ts_file.h"

bool
SSLSecret::loadSecret(const char *name, SSLSecretData &data_item)
{
  // Call the load secret hooks
  //
  class APIHook *curHook = lifecycle_hooks->get(TS_LIFECYCLE_SSL_SECRET_HOOK);
  TSSecretID secret_name;
  secret_name.name    = name;
  secret_name.version = data_item.version;
  while (curHook) {
    curHook->invoke(TS_EVENT_SSL_SECRET, const_cast<void *>(static_cast<const void *>(&secret_name)));
    curHook = curHook->next();
  }

  const SSLSecretData *data = this->getSecret(name);
  if (nullptr == data || data->data.length() == 0) {
    // If none of them load it, assume it is a file
    return loadFile(name, data_item.data);
  }
  return true;
}

bool
SSLSecret::loadFile(const char *name, std::string &data_item)
{
  struct stat statdata;
  // Load the secret and add it to the map
  if (stat(name, &statdata) < 0) {
    return false;
  }
  std::error_code error;
  data_item = ts::file::load(ts::file::path(name), error);
  if (error) {
    // Loading file failed
    return false;
  }
  if (SSLConfigParams::load_ssl_file_cb) {
    SSLConfigParams::load_ssl_file_cb(name);
  }
  return true;
}

bool
SSLSecret::setSecret(std::string name, int version, const char *data, int data_len)
{
  auto iter = secret_map.find(name);
  if (iter == secret_map.end()) {
    secret_map[name] = SSLSecretData();
    iter             = secret_map.find(name);
  }
  if (iter == secret_map.end()) {
    return false;
  }
  iter->second.data.assign(data, data_len);
  iter->second.version = version;
  Debug("ssl_secret", "Set secret=%10.s... to %s version %d", name.c_str(), iter->second.data.data(), iter->second.version);
  return true;
}

const SSLSecret::SSLSecretData *
SSLSecret::getSecret(std::string name) const
{
  auto iter = secret_map.find(name);
  if (iter == secret_map.end()) {
    return nullptr;
  }
  return &iter->second;
}

bool
SSLSecret::getSecret(std::string name, int &version, const char **data, int *data_len) const
{
  const SSLSecretData *data_item = this->getSecret(name);
  if (data_item) {
    Debug("ssl_secret", "Get secret=%10.s...  %s(%" PRId64 ") version %d", name.c_str(), data_item->data.data(),
          data_item->data.length(), data_item->version);
    if (data) {
      *data = data_item->data.data();
    }
    if (data_len) {
      *data_len = data_item->data.size();
    }
    version = data_item->version;
    return true;
  }
  return false;
}

bool
SSLSecret::getOrLoadSecret(const char *name, int &version, const char **data, int *data_len)
{
  if (this->getSecret(name, version, data, data_len)) {
    return true;
  }
  secret_map[name] = SSLSecretData();
  auto iter        = secret_map.find(name);
  if (iter == secret_map.end()) {
    return false;
  }
  iter->second.version = version;
  if (this->loadSecret(name, iter->second)) {
    if (data) {
      *data = iter->second.data.data();
    }
    if (data_len) {
      *data_len = iter->second.data.length();
    }
    version = iter->second.version;
    return true;
  }
  return false;
}
