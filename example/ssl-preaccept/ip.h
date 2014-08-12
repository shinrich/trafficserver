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
/*
 * IP library header.  Currently just extracted from the core
 * Would be nice to have a common library that could be used in 
 * both core and plugins some day
 */

#if !defined (_ip_h)
#define _ip_h

#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "ats-util.h"

namespace ip {

#if !defined(IN6_IS_ADDR_UNSPECIFIED)
static inline bool IN6_IS_ADDR_UNSPECIFIED(in6_addr const* addr) {
  uint64_t const* w = reinterpret_cast<uint64_t const*>(addr);
  return 0 == w[0] && 0 == w[1];
}
#endif

struct Addr; // forward declare.

/** A union to hold the standard IP address structures.
    By standard we mean @c sockaddr compliant.

    We use the term "endpoint" because these contain more than just the
    raw address, all of the data for an IP endpoint is present.

    @internal This might be useful to promote to avoid strict aliasing
    problems.  Experiment with it here to see how it works in the
    field.

    @internal @c sockaddr_storage is not present because it is so
    large and the benefits of including it are small. Use of this
    structure will make it easy to add if that becomes necessary.

 */
union Endpoint {
  typedef Endpoint self; ///< Self reference type.

  struct sockaddr         sa; ///< Generic address.
  struct sockaddr_in      sin; ///< IPv4
  struct sockaddr_in6     sin6; ///< IPv6

  /// Assign from @c Addr.
  self& operator = (
		   Addr const& src
		   );
  self& assign(sockaddr const* ip);

  /// Test for valid IP address.
  bool isValid() const;
  /// Set invalid
  self& invalidate();
  /// Test for IPv4.
  bool isIp4() const;
  /// Test for IPv6.
  bool isIp6() const;

  /// Set to be any address for family @a family.
  /// @a family must be @c AF_INET or @c AF_INET6.
  /// @return This object.
  self& setToAnyAddr(
    int family ///< Address family.
  );
  /// Set to be loopback for family @a family.
  /// @a family must be @c AF_INET or @c AF_INET6.
  /// @return This object.
  self& setToLoopback(
    int family ///< Address family.
  );

  /// Port in network order.
  in_port_t& port();
  /// Port in network order.
  in_port_t port() const;

  /// Address family.
  uint16_t family() const;
};

// --
/// Size in bytes of an IPv6 address.
static size_t const TS_IP6_SIZE = sizeof(in6_addr);

/// @return The @c sockaddr size for the family of @a addr.
inline size_t ats_ip_size(
  sockaddr const* addr ///< Address object.
) {
  return AF_INET == addr->sa_family ? sizeof(sockaddr_in)
    : AF_INET6 == addr->sa_family ? sizeof(sockaddr_in6)
    : 0
    ;
}
inline size_t ats_ip_size(
  Endpoint const* addr ///< Address object.
) {
  return AF_INET == addr->sa.sa_family ? sizeof(sockaddr_in)
    : AF_INET6 == addr->sa.sa_family ? sizeof(sockaddr_in6)
    : 0
    ;
}
/// @return The size of the IP address only.
inline size_t ats_ip_addr_size(
  sockaddr const* addr ///< Address object.
) {
  return AF_INET == addr->sa_family ? sizeof(in_addr_t)
    : AF_INET6 == addr->sa_family ? sizeof(in6_addr)
    : 0
    ;
}
inline size_t ats_ip_addr_size(
  Endpoint const* addr ///< Address object.
) {
  return AF_INET == addr->sa.sa_family ? sizeof(in_addr_t)
    : AF_INET6 == addr->sa.sa_family ? sizeof(in6_addr)
    : 0
    ;
}
  
/// Buffer size sufficient for IPv6 address and port.
static size_t const INET6_ADDRPORTSTRLEN = INET6_ADDRSTRLEN + 6;

/** Storage for an IP address.
    In some cases we want to store just the address and not the
    ancillary information (such as port, or flow data).
    @note This is not easily used as an address for system calls.
*/
struct Addr {
  typedef Addr self; ///< Self reference type.

  /// Default construct (invalid address).
  Addr() : _family(AF_UNSPEC) {}
  /// Construct as IPv4 @a addr.
  explicit Addr(
    in_addr_t addr ///< Address to assign.
  ) : _family(AF_INET) {
    _addr._ip4 = addr;
  }
  /// Construct as IPv6 @a addr.
  explicit Addr(
    in6_addr const& addr ///< Address to assign.
  ) : _family(AF_INET6) {
    _addr._ip6 = addr;
  }

  /// Construct from @c sockaddr.
  explicit Addr(sockaddr const* addr) {
    *this = addr;
  }

  void assign(sockaddr const *ip);

  /// Assign from IPv4 raw address.
  self& operator = (
    in_addr_t ip ///< Network order IPv4 address.
  );

  /// Assign from sockaddr.
  self& operator = (
    sockaddr const* ip ///< Populated sockaddr struct
  ) {
    this->assign(ip);
    return *this;
  }

  /** Load from string.
      The address is copied to this object if the conversion is successful,
      otherwise this object is invalidated.
      @return 0 on success, non-zero on failure.
  */
  int load(const ts::ConstBuffer &str);
  
  /** Output to a string.
      @return The string @a dest.
  */
  char* toString(
    char* dst, ///< [out] Destination string buffer.
    socklen_t len = INET6_ADDRSTRLEN ///< [in] Size of buffer.
  ) const;

  /** Return a normalized hash value.
      Ipv4 - the address in host order.
      Ipv6 - folded 32 bit of the address.
      Other - 0
  */
  size_t hash() const;

  /// Hash in functor style.
  /// Painful to do without in Boost.
  struct Hasher : std::unary_function<self, size_t> {
    size_t operator() (self const& ip) const {
      return ip.hash();
    }
  };

  /// Generic compare.
  int cmp(self const& that) const;

  /// Test for same address family.
  /// @c return @c true if @a that is the same address family as @a this.
  bool isCompatibleWith(self const& that);

  /// Get the address family.
  /// @return The address family.
  uint16_t family() const;
  /// Test for IPv4.
  bool isIp4() const;
  /// Test for IPv6.
  bool isIp6() const;

  /// Size of the address data.
  /// @return the number of bytes for the address data, 0 if invalid.
  size_t size() const;

  /// Test for validity.
  bool isValid() const { return _family == AF_INET || _family == AF_INET6; }
  /// Make invalid.
  self& invalidate() { _family = AF_UNSPEC; return *this; }
  /// Test for multicast
  bool isMulticast() const;

  uint16_t _family; ///< Protocol family.
  /// Address data.
  union {
    in_addr_t _ip4; ///< IPv4 address storage.
    in6_addr  _ip6; ///< IPv6 address storage.
    uint8_t   _byte[TS_IP6_SIZE]; ///< As raw bytes.
    uint32_t  _w[TS_IP6_SIZE/4]; ///< As 32 bit words.
    uint64_t  _qw[TS_IP6_SIZE/8]; ///< As 64 bit words.
  } _addr;

  ///< Pre-constructed invalid instance.
  static self const INVALID;
};

inline Addr&
Addr::operator = (in_addr_t ip) {
  _family = AF_INET;
  _addr._ip4 = ip;
  return *this;
}

inline void
Addr::assign(sockaddr const* sa) {
  switch(sa->sa_family) {

  case AF_INET:
  _family = AF_INET;
  _addr._ip4 = reinterpret_cast<sockaddr_in const*>(sa)->sin_addr.s_addr;
  break;

  case AF_INET6:
  _family = AF_INET6;
  memcpy(&_addr._ip6, &reinterpret_cast<sockaddr_in6 const*>(sa)->sin6_addr, sizeof(_addr._ip6));
  break;

  default: _family = AF_UNSPEC;
  break;
  }
}

inline uint16_t Addr::family() const { return _family; }
inline size_t Addr::size() const {
  return AF_INET6 == _family ? sizeof(_addr._ip6)
    : AF_INET == _family ? sizeof(_addr._ip4)
    : 0;
}

inline bool
Addr::isCompatibleWith(self const& that) {
  return this->isValid() && _family == that._family;
}

inline bool Addr::isIp4() const { return AF_INET == _family; }
inline bool Addr::isIp6() const { return AF_INET6 == _family; }

// Associated operators.
bool operator == (Addr const& lhs, sockaddr const* rhs);
inline bool operator == (sockaddr const* lhs, Addr const& rhs) {
  return rhs == lhs;
}
inline bool operator != (Addr const& lhs, sockaddr const* rhs) {
  return ! (lhs == rhs);
}
inline bool operator != (sockaddr const* lhs, Addr const& rhs) {
  return ! (rhs == lhs);
}
inline bool operator == (Addr const& lhs, Endpoint const& rhs) {
  return lhs == &rhs.sa;
}
inline bool operator == (Endpoint const& lhs, Addr const& rhs) {
  return &lhs.sa == rhs;
}
inline bool operator != (Addr const& lhs, Endpoint const& rhs) {
  return ! (lhs == &rhs.sa);
}
inline bool operator != (Endpoint const& lhs, Addr const& rhs) {
  return ! (rhs == &lhs.sa);
}
inline bool operator < (Addr const& lhs, Addr const& rhs) {
  return -1 == lhs.cmp(rhs);
}

inline bool operator >= (Addr const& lhs, Addr const& rhs) {
  return lhs.cmp(rhs) >= 0;
}

inline bool operator > (Addr const& lhs, Addr const& rhs) {
  return 1 == lhs.cmp(rhs);
}

inline bool operator <= (Addr const& lhs, Addr const& rhs) {
  return  lhs.cmp(rhs) <= 0;
}

/** Compare two addresses.
    This is useful for IPv4, IPv6, and the unspecified address type.
    If the addresses are of different types they are ordered

    Non-IP < IPv4 < IPv6

     - all non-IP addresses are the same ( including @c AF_UNSPEC )
     - IPv4 addresses are compared numerically (host order)
     - IPv6 addresses are compared byte wise in network order (MSB to LSB)

    @return
      - -1 if @a lhs is less than @a rhs.
      - 0 if @a lhs is identical to @a rhs.
      - 1 if @a lhs is greater than @a rhs.

    @internal This looks like a lot of code for an inline but I think it
    should compile down to something reasonable.
*/
inline int
Addr::cmp(self const& that) const {
  int zret = 0;
  uint16_t rtype = that._family;
  uint16_t ltype = _family;

  // We lump all non-IP addresses into a single equivalence class
  // that is less than an IP address. This includes AF_UNSPEC.
  if (AF_INET == ltype) {
    if (AF_INET == rtype) {
      in_addr_t la = ntohl(_addr._ip4);
      in_addr_t ra = ntohl(that._addr._ip4);
      if (la < ra) zret = -1;
      else if (la > ra) zret = 1;
      else zret = 0;
    } else if (AF_INET6 == rtype) { // IPv4 < IPv6
      zret = -1;
    } else { // IP > not IP
      zret = 1;
    }
  } else if (AF_INET6 == ltype) {
    if (AF_INET6 == rtype) {
      zret = memcmp(&_addr._ip6, &that._addr._ip6, TS_IP6_SIZE);
    } else {
      zret = 1; // IPv6 greater than any other type.
    }
  } else if (AF_INET == rtype || AF_INET6 == rtype) {
    // ltype is non-IP so it's less than either IP type.
    zret = -1;
  } else {
    // Both types are non-IP so they're equal.
    zret = 0;
  }

  return zret;
}

/// Equality.
/// @internal distinct from cmp for performance.
inline bool operator ==(Addr const& lhs, Addr const& rhs) {
  return lhs._family == AF_INET
  ? (rhs._family == AF_INET && lhs._addr._ip4 == rhs._addr._ip4)
  : lhs._family == AF_INET6
  ? (rhs._family == AF_INET6
     && 0 == memcmp(&lhs._addr._ip6, &rhs._addr._ip6, TS_IP6_SIZE)
     )
  : (lhs._family == AF_UNSPEC && rhs._family == AF_UNSPEC)
  ;
}

inline bool operator !=(Addr const& lhs, Addr const& rhs) {
  return !(lhs == rhs);
}

inline size_t
Addr::hash() const {
  size_t zret = 0;
  if (this->isIp4()) {
    zret = ntohl(_addr._ip4);
  } else if (this->isIp6()) {
    zret = _addr._w[0] ^ _addr._w[1] ^ _addr._w[2] ^ _addr._w[3];
  }
  return zret;
}

inline Endpoint&
Endpoint::assign(sockaddr const* ip) {
  size_t n = 0;
  if (ip) {
    switch (ip->sa_family) {
    case AF_INET: n = sizeof(sockaddr_in); break;
    case AF_INET6: n = sizeof(sockaddr_in6); break;
    }
  }
  if (n) {
    memcpy(&sa, ip, n);
#if HAVE_STRUCT_SOCKADDR_SA_LEN
    dst->sa_len = n;
#endif
  } else {
    this->invalidate();
  }
  return *this;
}

inline in_port_t&
Endpoint::port() {
  static in_port_t dummy = 0;
  return this->isIp4() ? sin.sin_port
    : this->isIp6() ? sin6.sin6_port
    : (dummy = 0)
    ;
}

inline in_port_t
Endpoint::port() const {
  return const_cast<self*>(this)->port(); // Call the non-const version
}

inline bool
Endpoint::isValid() const {
  return this->isIp4() || this->isIp6();
}

inline uint16_t Endpoint::family() const { return sa.sa_family; }
inline bool Endpoint::isIp4() const { return AF_INET == sa.sa_family; }
inline bool Endpoint::isIp6() const { return AF_INET6 == sa.sa_family; }

inline Endpoint&
Endpoint::invalidate() {
  sa.sa_family = AF_UNSPEC;
  return *this;
}

inline Endpoint&
Endpoint::setToAnyAddr(int family) {
  ink_zero(*this);
  sa.sa_family = family;
  if (AF_INET == family) {
    sin.sin_addr.s_addr = INADDR_ANY;
#if HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sin.sin_len = sizeof(sockaddr_in);
#endif
  } else if (AF_INET6 == family) {
    sin6.sin6_addr = in6addr_any;
#if HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
    sin6.sin6_len = sizeof(sockaddr_in6);
#endif
  }
  return *this;
}

inline Endpoint&
Endpoint::setToLoopback(int family) {
  ink_zero(*this);
  sa.sa_family = family;
  if (AF_INET == family) {
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#if HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sin.sin_len = sizeof(sockaddr_in);
#endif
  } else if (AF_INET6 == family) {
    sin6.sin6_addr = in6addr_loopback;
#if HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
    sin6.sin6_len = sizeof(sockaddr_in6);
#endif
  }
  return *this;
}

inline Endpoint&
Endpoint::operator = (Addr const& src) {
  ink_zero(*this);
  sa.sa_family = src._family;
  if (AF_INET == src._family) {
    sin.sin_addr.s_addr = src._addr._ip4;
#if HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sin.sin_len = sizeof(sockaddr_in);
#endif
  } else if (AF_INET6 == src._family) {
    sin6.sin6_addr = src._addr._ip6;
#if HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
    sin6.sin6_len = sizeof(sockaddr_in6);
#endif
  }
  return *this;
}

} // namespace ip

/// Reset an address to invalid.
/// @note Useful for marking a member as not yet set.
inline void ats_ip_invalidate(sockaddr* addr) {
  addr->sa_family = AF_UNSPEC;
}
inline void ats_ip_invalidate(sockaddr_in6* addr) {
  addr->sin6_family = AF_UNSPEC;
}
inline void ats_ip_invalidate(ip::Endpoint* ip) {
  ip->sa.sa_family = AF_UNSPEC;
}

// IP address casting.
// sa_cast to cast to sockaddr*.
// ss_cast to cast to sockaddr_storage*.
// ip4_cast converts to sockaddr_in (because that's effectively an IPv4 addr).
// ip6_cast converts to sockaddr_in6

inline sockaddr* ats_ip_sa_cast(sockaddr_storage* a) {
  return static_cast<sockaddr*>(static_cast<void*>(a));
}
inline sockaddr const* ats_ip_sa_cast(sockaddr_storage const* a) {
  return static_cast<sockaddr const*>(static_cast<void const*>(a));
}

inline sockaddr* ats_ip_sa_cast(sockaddr_in* a) {
  return static_cast<sockaddr*>(static_cast<void*>(a));
}
inline sockaddr const* ats_ip_sa_cast(sockaddr_in const* a) {
  return static_cast<sockaddr const*>(static_cast<void const*>(a));
}

inline sockaddr* ats_ip_sa_cast(sockaddr_in6* a) {
  return static_cast<sockaddr*>(static_cast<void*>(a));
}
inline sockaddr const* ats_ip_sa_cast(sockaddr_in6 const* a) {
  return static_cast<sockaddr const*>(static_cast<void const*>(a));
}

inline sockaddr_in* ats_ip4_cast(sockaddr* a) {
  return static_cast<sockaddr_in*>(static_cast<void*>(a));
}
inline sockaddr_in const* ats_ip4_cast(sockaddr const* a) {
  return static_cast<sockaddr_in const*>(static_cast<void const*>(a));
}

inline sockaddr_in& ats_ip4_cast(sockaddr& a) {
  return *static_cast<sockaddr_in*>(static_cast<void*>(&a));
}
inline sockaddr_in const& ats_ip4_cast(sockaddr const& a) {
  return *static_cast<sockaddr_in const*>(static_cast<void const*>(&a));
}

inline sockaddr_in* ats_ip4_cast(sockaddr_in6* a) {
  return static_cast<sockaddr_in*>(static_cast<void*>(a));
}
inline sockaddr_in const* ats_ip4_cast(sockaddr_in6 const* a) {
  return static_cast<sockaddr_in const*>(static_cast<void const*>(a));
}

inline sockaddr_in& ats_ip4_cast(sockaddr_in6& a) {
  return *static_cast<sockaddr_in*>(static_cast<void*>(&a));
}
inline sockaddr_in const& ats_ip4_cast(sockaddr_in6 const& a) {
  return *static_cast<sockaddr_in const*>(static_cast<void const*>(&a));
}
inline sockaddr_in6* ats_ip6_cast(sockaddr* a) {
  return static_cast<sockaddr_in6*>(static_cast<void*>(a));
}
inline sockaddr_in6 const* ats_ip6_cast(sockaddr const* a) {
  return static_cast<sockaddr_in6 const*>(static_cast<void const*>(a));
}
inline sockaddr_in6& ats_ip6_cast(sockaddr& a) {
  return *static_cast<sockaddr_in6*>(static_cast<void*>(&a));
}
inline sockaddr_in6 const& ats_ip6_cast(sockaddr const& a) {
  return *static_cast<sockaddr_in6 const*>(static_cast<void const*>(&a));
}

inline bool ats_is_ip(sockaddr const* addr) {
  return addr
    && (AF_INET == addr->sa_family || AF_INET6 == addr->sa_family);
}
/// @return @c true if the address is IP, @c false otherwise.
inline bool ats_is_ip(ip::Endpoint const* addr) {
  return addr
    && (AF_INET == addr->sa.sa_family || AF_INET6 == addr->sa.sa_family);
}
/// Test for IP protocol.
/// @return @c true if the value is an IP address family, @c false otherwise.
inline bool ats_is_ip(int family) {
  return AF_INET == family || AF_INET6 == family;
}

/// Test for IPv4 protocol.
// @return @c true if the address is IPv4, @c false otherwise.
inline bool ats_is_ip4(sockaddr const* addr) {
  return addr && AF_INET == addr->sa_family;
}
/// Test for IPv4 protocol.
/// @note Convenience overload.
/// @return @c true if the address is IPv4, @c false otherwise.
inline bool ats_is_ip4(ip::Endpoint const* addr) {
  return addr && AF_INET == addr->sa.sa_family;
}
/// Test for IPv6 protocol.
/// @return @c true if the address is IPv6, @c false otherwise.
inline bool ats_is_ip6(sockaddr const* addr) {
  return addr && AF_INET6 == addr->sa_family;
}
/// Test for IPv6 protocol.
/// @note Convenience overload.
/// @return @c true if the address is IPv6, @c false otherwise.
inline bool ats_is_ip6(ip::Endpoint const* addr) {
  return addr && AF_INET6 == addr->sa.sa_family;
}


inline sockaddr* ats_ip4_set(
  sockaddr_in* dst, ///< Destination storage.
  in_addr_t addr, ///< address, IPv4 network order.
  in_port_t port = 0 ///< port, network order.
) {
  ink_zero(*dst);
#if HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
  dst->sin_len = sizeof(sockaddr_in);
#endif
  dst->sin_family = AF_INET;
  dst->sin_addr.s_addr = addr;
  dst->sin_port = port;
  return ats_ip_sa_cast(dst);
}

/** Write IPv4 data to @a dst.
    @note Convenience overload.
 */
inline sockaddr* ats_ip4_set(
  ip::Endpoint* dst, ///< Destination storage.
  in_addr_t ip4, ///< address, IPv4 network order.
  in_port_t port = 0 ///< port, network order.
) {
  return ats_ip4_set(&dst->sin, ip4, port);
}

/** Write IPv4 data to storage @a dst.
 
    This is the generic overload. Caller must verify that @a dst is at
    least @c sizeof(sockaddr_in) bytes.
 */
inline sockaddr* ats_ip4_set(
  sockaddr* dst, ///< Destination storage.
  in_addr_t ip4, ///< address, IPv4 network order.
  in_port_t port = 0 ///< port, network order.
) {
  return ats_ip4_set(ats_ip4_cast(dst), ip4, port);
}

/** Write IPv6 data to storage @a dst.
    @return @a dst cast to @c sockaddr*.
 */
inline sockaddr* ats_ip6_set(
  sockaddr_in6* dst, ///< Destination storage.
  in6_addr const& addr, ///< address in network order.
  in_port_t port = 0 ///< Port, network order.
) {
  ink_zero(*dst);
#if HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
  dst->sin6_len = sizeof(sockaddr_in6);
#endif
  dst->sin6_family = AF_INET6;
  memcpy(&dst->sin6_addr, &addr, sizeof addr);
  dst->sin6_port = port;
  return ats_ip_sa_cast(dst);
}
/** Write IPv6 data to storage @a dst.
    @return @a dst cast to @c sockaddr*.
 */
inline sockaddr* ats_ip6_set(
  sockaddr* dst, ///< Destination storage.
  in6_addr const& addr, ///< address in network order.
  in_port_t port = 0 ///< Port, network order.
) {
  return ats_ip6_set(ats_ip6_cast(dst), addr, port);
}
/** Write IPv6 data to storage @a dst.
    @return @a dst cast to @c sockaddr*.
 */
inline sockaddr* ats_ip6_set(
  ip::Endpoint* dst, ///< Destination storage.
  in6_addr const& addr, ///< address in network order.
  in_port_t port = 0 ///< Port, network order.
) {
  return ats_ip6_set(&dst->sin6, addr, port);
}

/** Get a reference to the port in an address.
    @note Because this is direct access, the port value is in network order.
    @see ats_ip_port_host_order.
    @return A reference to the port value in an IPv4 or IPv6 address.
    @internal This is primarily for internal use but it might be handy for
    clients so it is exposed.
*/
inline in_port_t& ats_ip_port_cast(sockaddr* sa) {
  static in_port_t dummy = 0;
  return ats_is_ip4(sa)
    ? ats_ip4_cast(sa)->sin_port
    : ats_is_ip6(sa)
      ? ats_ip6_cast(sa)->sin6_port
      : (dummy = 0)
    ;
}
inline in_port_t const& ats_ip_port_cast(sockaddr const* sa) {
  return ats_ip_port_cast(const_cast<sockaddr*>(sa));
}
inline in_port_t const& ats_ip_port_cast(ip::Endpoint const* ip) {
  return ats_ip_port_cast(const_cast<sockaddr*>(&ip->sa));
}
inline in_port_t& ats_ip_port_cast(ip::Endpoint* ip) {
  return ats_ip_port_cast(&ip->sa);
}



#endif // _ip_h
