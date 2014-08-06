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

#ifndef __P_SSLCERTLOOKUP_H__
#define __P_SSLCERTLOOKUP_H__

#include "ProxyConfig.h"
#include "P_SSLUtils.h"

struct SSLConfigParams;
struct SSLContextStorage;

/** A certificate context.

    This holds data about a certificate and how it is used by the SSL logic. Current this is mainly
    the openSSL certificate and an optional action, which in turn is limited to just tunneling.

    Instances are passed around and returned when matching connections to certificates.

    Instances of this class are stored on a list and then referenced via index in that list so that
    there is exactly one place we can find all the @c SSL_CTX instances exactly once.

*/
struct SSLCertContext
{
  /** Special things to do instead of use a context.
      In general an option will be associated with a @c NULL context because
      the context is not used.
  */
  enum Option {
    OPT_NONE, ///< Nothing special. Implies valid context.
    OPT_TUNNEL ///< Just tunnel, don't terminate.
  };

  SSLCertContext() : ctx(0), opt(OPT_NONE) {}
  explicit SSLCertContext(SSL_CTX* c) : ctx(c), opt(OPT_NONE) {}
  SSLCertContext(SSL_CTX* c, Option o) : ctx(c), opt(o) {}
  
  SSL_CTX* ctx; ///< openSSL context.
  Option opt; ///< Special handling option.
};

struct SSLCertLookup : public ConfigInfo
{
  SSLContextStorage * ssl_storage;
  SSL_CTX *           ssl_default;

  bool insert(SSL_CTX * ctx, const char * name);
  bool insert(SSL_CTX * ctx, const IpEndpoint& address);

  /** Find certificate context by IP address.
      The IP addresses are taken from the socket @a s.
      Exact matches have priority, then wildcards. The destination address is preferred to the source address.
      @return @c A pointer to the matched context, @c NULL if no match is found.
  */
  SSLCertContext* find(const IpEndpoint& address) const;

  /** Find certificate context by name (FQDN).
      Exact matches have priority, then wildcards. Only destination based matches are checked.
      @return @c A pointer to the matched context, @c NULL if no match is found.
  */
  SSLCertContext* find(char const* name) const;



  // Return the last-resort default TLS context if there is no name or address match.
  SSL_CTX * defaultContext() const { return ssl_default; }

  unsigned count() const;
  SSL_CTX * get(unsigned i) const;

  SSLCertLookup();
  virtual ~SSLCertLookup();
};

#endif /* __P_SSLCERTLOOKUP_H__ */
