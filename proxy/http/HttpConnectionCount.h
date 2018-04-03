/** @file

  A brief file description

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

#pragma once

#include <chrono>
#include <atomic>
#include <sstream>
#include <tuple>
#include <ts/ink_platform.h>
#include <ts/ink_config.h>
#include <ts/ink_mutex.h>
#include <ts/ink_inet.h>
#include <ts/Map.h>
#include <ts/Diags.h>
#include <ts/CryptoHash.h>
#include "HttpProxyAPIEnums.h"
#include "Show.h"

namespace ts
{
/// Format the session sharing enum.
// This needs to be moved elsewhere.
inline BufferWriter &
bwformat(BufferWriter &w, BWFSpec const &spec, TSServerSessionSharingMatchType type)
{
  static const string_view name[] = {"None"_sv, "Both"_sv, "IP"_sv, "Host"_sv};
  if (spec.has_numeric_type()) {
    bwformat(w, spec, static_cast<unsigned int>(type));
  } else {
    bwformat(w, spec, name[type]);
  }
  return w;
}
} // ts

/**
 * Singleton class to keep track of the number of outbound connnections.
 *
 * Outbound connections are divided in to equivalence classes (called "groups" here) based on the
 * session matching setting. Tracking data is stored for each group.
 */
class OutboundConnTracker
{
  using self_type = OutboundConnTracker; ///< Self reference type.

public:
  // Non-copyable.
  OutboundConnTracker(const self_type &) = delete;
  self_type &operator=(const self_type &) = delete;

  /// A record for the outbound connection count.
  /// These are stored per outbound session equivalence class, as determined by the session matching.
  struct Group {
    /// Equivalence key - two groups are equivalent if their keys are equal.
    struct Key {
      IpEndpoint const &_addr; ///< Remote IP address.
      CryptoHash const &_fqdn_hash; ///< Hash of the FQDN.
      TSServerSessionSharingMatchType _match_type; ///< Type of matching.
    };

    /// Time point type, based on the clock to be used.
    using Time   = std::chrono::high_resolution_clock::time_point;
    using Ticker = Time::rep; ///< Raw type used to track HR ticks.
    /// Length of time to suppress alerts for a group.
    static const std::chrono::seconds ALERT_DELAY;

    IpEndpoint _addr;                            ///< Remote address & port.
    CryptoHash _fqdn_hash;                       ///< Hash of the host name.
    TSServerSessionSharingMatchType _match_type; ///< Outbound session matching type.
    std::atomic<int> _count{0};                  ///< Number of outbound connections.
    std::atomic<Ticker> _last_alert{0};          ///< Absolute time of the last alert.
    std::atomic<int> _blocked{0};                ///< Number of outbound connections blocked since last alert.
    std::atomic<int> _queued{0};                 ///< # of connections queued, waiting for a connection.
    LINK(Group, _link);                          ///< Intrusive hash table support.
    Key _key = {_addr, _fqdn_hash, _match_type}; ///< Pre-constructed key for performance on lookup.

    /// Constructor.
    Group(Key const &key);
    /// Key equality checker.
    static bool equal(Key const &lhs, Key const &rhs);
    /// Hashing function.
    static uint64_t hash(Key const &);
    /// Check and clear alert enable.
    /// This is a modifying call - internal state will be updated to prevent too frequent alerts.
    /// @param lat The last alert time, in epoch seconds, if the method returns @c true.
    /// @return @c true if an alert was generated, @c false otherwise.
    bool should_alert(std::time_t * lat = nullptr);
    /// Time of the last alert in epoch seconds.
    std::time_t get_last_alert_epoch_time() const;
  };

  /**
   * Get the @c Group for the specified session properties.
   * @param ip IP address and port of the host.
   * @param hostname_hash Hash of the FQDN for the host.
   * @param match_type Session matching type.
   * @return Number of connections
   *
   * This should already return a valid @c Group - if the group does yet exist, it is created.
   */
  static Group *get(const IpEndpoint &addr, const CryptoHash &hostname_hash, TSServerSessionSharingMatchType match_type);

  /**
   * Get groups under lock.
   * @param groups OUT parameter - pointers to the groups are pushed in to this container.
   *
   * The groups are loaded in to @a groups, which is cleared before loading. Note the groups returned will remain valid
   * although data inside the groups is volatile.
   */
  static void get(std::vector<Group const*>& groups);
  /**
   * Write the connection tracking data to JSON.
   * @return string containing a JSON encoding of the table.
   */
  static std::string to_json_string();
  /**
   * Write the groups to @a f.
   * @param f Output file.
   */
  static void dump(FILE *f);

protected:
  /// Types and methods for the hash table.
  struct HashDescriptor {
    using ID       = uint64_t;
    using Key      = Group::Key const &;
    using Value    = Group;
    using ListHead = DList(Value, _link);

    static ID
    hash(Key key)
    {
      return Group::hash(key);
    }
    static Key
    key(Value *v)
    {
      return v->_key;
    }
    static bool
    equal(Key lhs, Key rhs)
    {
      return Group::equal(lhs, rhs);
    }
  };

  /// Container type for the connection groups.
  using HashTable = TSHashTable<HashDescriptor>;

  /// Internal implementation class instance.
  struct Imp {
    Imp();

    HashTable _table; ///< Hash table of upstream groups.
    ink_mutex _mutex; ///< Lock for insert & find.
  };
  static Imp _imp;

  /// Get the implementation instance.
  /// @note This is done purely to provide subclasses to reuse methods in this class.
  Imp &instance();
};

inline OutboundConnTracker::Imp::Imp()
{
  ink_mutex_init(&_mutex, "OutboundConnTrack");
};

inline OutboundConnTracker::Imp &
OutboundConnTracker::instance()
{
  return _imp;
}

inline OutboundConnTracker::Group *
OutboundConnTracker::get(IpEndpoint const &addr, CryptoHash const &fqdn_hash, TSServerSessionSharingMatchType match_type)
{
  if (TS_SERVER_SESSION_SHARING_MATCH_NONE == match_type) {
    return 0; // We can never match a node if match type is NONE
  }

  Group::Key key{addr, fqdn_hash, match_type};
  Group *g = nullptr;
  ink_scoped_mutex_lock lock(_imp._mutex); // TABLE LOCK
  auto loc = _imp._table.find(key);
  if (loc.isValid()) {
    g = loc;
  } else {
    g = new Group(key);
    _imp._table.insert(g);
  }
  return g;
}

inline bool
OutboundConnTracker::Group::equal(const Key &lhs, const Key &rhs)
{
  TSServerSessionSharingMatchType mt = lhs._match_type;
  bool zret = mt == rhs._match_type && (mt == TS_SERVER_SESSION_SHARING_MATCH_IP || lhs._fqdn_hash == rhs._fqdn_hash) &&
              (mt == TS_SERVER_SESSION_SHARING_MATCH_HOST || ats_ip_addr_port_eq(&lhs._addr.sa, &rhs._addr.sa));

  if (is_debug_tag_set("conn_count")) {
    ts::LocalBufferWriter<256> bw;
    bw.print("Comparing {}:{::p}:{} to {}:{::p}:{} -> {}", lhs._fqdn_hash, lhs._addr, lhs._match_type, rhs._fqdn_hash, rhs._addr,
             rhs._match_type, zret ? "match" : "fail");
    Debug("conn_count", "%.*s", static_cast<int>(bw.size()), bw.data());
  }

  return zret;
}

inline uint64_t
OutboundConnTracker::Group::hash(const Key &key)
{
  switch (key._match_type) {
  case TS_SERVER_SESSION_SHARING_MATCH_IP:
    return ats_ip_port_hash(&key._addr.sa);
  case TS_SERVER_SESSION_SHARING_MATCH_HOST:
    return key._fqdn_hash.fold();
  case TS_SERVER_SESSION_SHARING_MATCH_BOTH:
    return ats_ip_port_hash(&key._addr.sa) ^ key._fqdn_hash.fold();
  default:
    return 0;
  }
}

inline OutboundConnTracker::Group::Group(const Key &key) : _fqdn_hash(key._fqdn_hash), _match_type(key._match_type)
{
  ats_ip_copy(_addr, &key._addr);
  _key._match_type = _match_type; // make sure this gets updated.
}

Action *register_ShowConnectionCount(Continuation *, HTTPHdr *);
