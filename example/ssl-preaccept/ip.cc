/** @file 
    Implementation for the ip address library
*/
# include <stdio.h>
# include <tsconfig/TsValue.h>
# include "ip.h"

int
ats_ip_parse(ts::ConstBuffer src, ts::ConstBuffer* addr, ts::ConstBuffer* port) {
  // In case the incoming arguments are null.
  ts::ConstBuffer localAddr, localPort;
  if (!addr) addr = &localAddr;
  if (!port) port = &localPort;
  addr->reset();
  port->reset();
  
  // Let's see if we can find out what's in the address string.
  if (src) {
    while (src && isspace(*src)) ++src;
    // Check for brackets.
    if ('[' == *src) {
      /* Ugly. In a number of places we must use bracket notation
        to support port numbers. Rather than mucking with that
        everywhere, we'll tweak it here. Experimentally we can't
        depend on getaddrinfo to handle it. Note that the text
        buffer size includes space for the nul, so a bracketed
        address is at most that size - 1 + 2 -> size+1.

        It just gets better. In order to bind link local addresses
        the scope_id must be set to the interface index. That's
        most easily done by appending a %intf (where "intf" is the
        name of the interface) to the address. Which makes
        the address potentially larger than the standard maximum.
        So we can't depend on that sizing.
      */
      ++src; // skip bracket. 
      *addr = src.splitOn(']');
      if (*addr && ':' == *src) { // found the closing bracket and port colon
        ++src; // skip colon.
        *port = src;
      } // else it's a fail for unclosed brackets.
    } else {
      // See if there's exactly 1 colon
      ts::ConstBuffer tmp = src.after(':');
      if (tmp && ! tmp.find(':')) { // 1 colon and no others
        src.clip(tmp.data() - 1); // drop port from address.
        *port = tmp;
      } // else 0 or > 1 colon and no brackets means no port.
      *addr = src;
    }
    // clip port down to digits.
    if (*port) {
      char const* spot = port->data();
      while (isdigit(*spot)) ++spot;
      port->clip(spot);
    }
  }
  return *addr ? 0 : -1; // true if we found an address.
}

int
ats_ip_pton(const ts::ConstBuffer& src, sockaddr* ip)
{
  int zret = -1;
  ts::ConstBuffer addr, port;

  ats_ip_invalidate(ip);
  if (0 == ats_ip_parse(src, &addr, &port)) {
    // Copy if not terminated.
    if (0 != addr[addr.size()-1]) {
       char* tmp = static_cast<char*>(alloca(addr.size()+1));
       memcpy(tmp, addr.data(), addr.size());
       tmp[addr.size()] = 0;
       addr.set(tmp, addr.size());
    }
    if (addr.find(':')) { // colon -> IPv6
        in6_addr addr6;
        if (inet_pton(AF_INET6, addr.data(), &addr6)) {
          zret = 0;
          ats_ip6_set(ip, addr6);
        }
      } else { // no colon -> must be IPv4
        in_addr addr4;
        if (inet_aton(addr.data(), &addr4)) {
        zret = 0;
        ats_ip4_set(ip, addr4.s_addr);
      }
    }
    // If we had a successful conversion, set the port.
    if (ats_is_ip(ip))
      ats_ip_port_cast(ip) = port ? htons(atoi(port.data())) : 0;
    }
    return zret;
}

    
int 
ip::Addr::load(const ts::ConstBuffer &text) 
{
  ip::Endpoint ip;
  int zret = ats_ip_pton(text, &ip.sa);
  this->assign(&ip.sa);
  return zret;
}


char*
ip::Addr::toString(char* dst, socklen_t len) const {
  switch (_family) {
  case AF_INET:
    inet_ntop(AF_INET, &_addr._ip4, dst, len);
    break;
  case AF_INET6:
    inet_ntop(AF_INET6, &_addr._ip6, dst, len);
    break;
  default:
    snprintf(dst, len, "*Not IP address [%u]*", _family);
    break;
  }
  return dst;
}
