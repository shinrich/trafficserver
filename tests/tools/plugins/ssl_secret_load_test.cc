/** @file

  SSL Preaccept test plugin
  Implements blind tunneling based on the client IP address
  The client ip addresses are specified in the plugin's
  config file as an array of IP addresses or IP address ranges under the
  key "client-blind-tunnel"

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

#include <ts/ts.h>
#include <openssl/ssl.h>
#include <strings.h>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>

#define PN "ssl_secret_load_test"
#define PCP "[" PN " Plugin] "

int
CB_Load_Secret(TSCont cont, TSEvent event, void *edata)
{
  TSSecretID *id = reinterpret_cast<TSSecretID *>(edata);

  TSDebug(PN, "Load secret for %s version=%d", id->name, id->version);

  std::string data_item;
  struct stat statdata;

  // insert the "ssl" directory into the path
  std::string path(id->name);
  std::string newname;
  auto offset = path.find_last_of("/");
  if (offset == std::string::npos) {
    newname = "ssl/";
    newname.append(id->name);
  } else {
    newname = path.substr(0, offset + 1);
    newname.append("ssl/");
    newname.append(path.substr(offset + 1));
  }
  TSDebug(PN, "Really load secret for %s", newname.c_str());

  // Load the secret and add it to the map
  if (stat(newname.c_str(), &statdata) < 0) {
    return TS_ERROR;
  }

  int fd = open(newname.c_str(), O_RDONLY);
  if (fd < 0) {
    TSDebug(PN, "Failed to load %s", newname.c_str());
    return TS_ERROR;
  }
  size_t total_size = statdata.st_size;
  data_item.resize(total_size);
  offset     = 0;
  char *data = data_item.data();
  while (offset < total_size) {
    int num_read = read(fd, data + offset, total_size - offset);
    if (num_read < 0) {
      close(fd);
      return TS_ERROR;
    }
    offset += num_read;
  }
  close(fd);

  TSSslSecretSet(id->name, strlen(id->name), id->version, data, total_size);

  return TS_SUCCESS;
}

// Called by ATS as our initialization point
void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;
  info.plugin_name   = const_cast<char *>("SSL secret load test");
  info.vendor_name   = const_cast<char *>("apache");
  info.support_email = const_cast<char *>("shinrich@apache.org");
  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] Plugin registration failed", PN);
  }

  TSCont cb = TSContCreate(&CB_Load_Secret, nullptr);
  TSLifecycleHookAdd(TS_LIFECYCLE_SSL_SECRET_HOOK, cb);

  return;
}
