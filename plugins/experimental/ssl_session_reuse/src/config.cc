/** @file

  config.cc - config file support

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
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ts/TextView.h>
#include <unistd.h>

#include "Config.h"
#include "common.h"

template <> Config *Singleton<Config>::ms_Singleton = NULL;

Config::Config()
{
  m_filename = "";
  m_config.clear();
  pthread_mutex_init(&m_yconfigLock, NULL);
  m_noConfig      = false;
  m_alreadyLoaded = false;
  m_lastCheck     = 0;
  m_lastmtime     = 0;
}

Config::~Config()
{
  pthread_mutex_destroy(&m_yconfigLock);
}

bool
Config::loadConfig(const std::string &filename)
{
  if (m_alreadyLoaded) {
    return true;
  }

  bool success = false;

  m_filename = filename;

  int fd = (this->m_filename.length() > 0 ? open(m_filename.c_str(), O_RDONLY) : 0);
  struct stat info;
  if (0 == fstat(fd, &info)) {
    size_t n = info.st_size;
    std::string config_data;
    config_data.reserve(n);
    auto read_len = read(fd, config_data.data(), n);
    if (read_len > 0) {
      config_data.resize(read_len);
    }

    ts::TextView content(config_data);
    while (content) {
      ts::TextView line = content.take_prefix_at('\n');
      if (line.empty() || '#' == *line) {
        continue;
      } else {
        return false;
      }
      line.ltrim_if(&isspace);
      ts::TextView field = line.take_prefix_at('=');
      TSDebug(PLUGIN, "%.*s=%.*s", static_cast<int>(field.size()), field.data(), static_cast<int>(line.size()), line.data());
      m_config[std::string(field.data(), field.size())] = std::string(line.data(), line.size());
    }
  }
  m_noConfig      = false;
  success         = true;
  m_alreadyLoaded = true;
  //
  //    // update the last mtime.
  //    setLastConfigChange();
  //  }

  return success;
}

bool
Config::setLastConfigChange()
{
  struct stat s;
  time_t oldLastmtime = m_lastmtime;

  memset(&s, 0, sizeof(s));
  stat(m_filename.c_str(), &s);

  m_lastmtime = s.st_mtim.tv_sec;

  if (s.st_mtim.tv_sec > oldLastmtime) {
    return true;
  }
  return false;
}

bool
Config::configHasChanged()
{
  time_t checkTime = time(0) / cCheckDivisor;

  if (0 == m_lastmtime || m_lastCheck != checkTime) {
    m_lastCheck = checkTime;
    return setLastConfigChange();
  }
  return false;
}

bool
Config::loadConfigOnChange()
{
  if (configHasChanged()) {
    // loadConfig will check this, and if it hasn't been set it'll just bail.
    m_alreadyLoaded = false;
    return loadConfig(m_filename);
  }

  return true;
}

bool
Config::getValue(const std::string &category, const std::string &key, std::string &value)
{
  if (!m_noConfig) {
    pthread_mutex_lock(&m_yconfigLock);

    if (loadConfigOnChange()) {
      // convert to category.key= value.
      std::string keyname                             = category + "." + key;
      std::map<std::string, std::string>::iterator it = m_config.find(keyname);

      // we have to use find so we don't overwrite defaults when we don't find anything.
      if (m_config.end() != it) {
        value = it->second;
      }
    }

    pthread_mutex_unlock(&m_yconfigLock);
  }

  return !value.empty();
}
