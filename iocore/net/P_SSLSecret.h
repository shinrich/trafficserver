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

class SSLSecret
{
public:
  SSLSecret() {}
  bool loadFile(const char *name, std::string &data_item);
  bool getSecret(std::string name, int &version, const char **data, int *data_len) const;
  bool setSecret(std::string name, int version, const char *data, int data_len);
  bool getOrLoadSecret(const char *name, int &version, const char **data, int *data_len);

private:
  class SSLSecretData
  {
  public:
    SSLSecretData() {}
    std::string data;
    int version = -1;
  };
  const SSLSecretData *getSecret(std::string name) const;
  bool loadSecret(const char *name, SSLSecretData &data_item);

  std::unordered_map<std::string, SSLSecretData> secret_map;
};
