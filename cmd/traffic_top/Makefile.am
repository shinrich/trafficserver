#
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# We only build tstop if libcurses and libcurl are available.
if BUILD_TSTOP

AM_CPPFLAGS = \
  -I$(top_srcdir)/mgmt/api/include \
  @CURL_CFLAGS@

AM_LDFLAGS = \
  @EXTRA_CXX_LDFLAGS@ \
  @LIBTOOL_LINK_FLAGS@ \
  @OPENSSL_LDFLAGS@

bin_PROGRAMS = traffic_top

traffic_top_SOURCES = traffic_top.cc

# Why can't this go in AM_CPPFLAGS? I have no idea, but it doesn't work. Because the
# CXX flags are used with the linker and not the compiler?
# traffic_top_CXXFLAGS works but causes traffic_top-traffic_top.o to be generated.
AM_CXXFLAGS += -Wl,--add-needed

traffic_top_LDADD = \
  $(top_builddir)/mgmt/api/libtsmgmt.la \
  @CURL_LIBS@ @CURSES_LIB@

# Install a compatibility symlink because traffic_top was named tstop in previous releases.
install-exec-hook:
	cd $(DESTDIR)$(bindir) && $(RM) tstop && $(LN_S) traffic_top tstop

endif
