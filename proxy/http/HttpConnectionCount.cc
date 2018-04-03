/** @file

  Outbound connection tracking support.

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

#include "HttpConnectionCount.h"

OutboundConnTracker::Imp OutboundConnTracker::_imp;
const std::chrono::seconds OutboundConnTracker::Group::ALERT_DELAY{60};

bool
OutboundConnTracker::Group::should_alert(std::time_t* lat)
{
  bool zret = false;
  // This is a bit clunky because the goal is to store just the tick count as an atomic.
  // Might check to see if an atomic time_point is really atomic and avoid this.
  Ticker last_tick{_last_alert}; // Load the most recent alert time in ticks.
  Time last{Time::duration{last_tick}}; // Most recent alert time in a time_point.
  Time now = std::chrono::high_resolution_clock::now(); // Current time_point.
  if (last + ALERT_DELAY <= now) {
    // it's been long enough, swap out our time for the last time. The winner of this swap
    // does the actual alert, leaving its current time as the last alert time.
    zret = _last_alert.compare_exchange_strong(last_tick, now.time_since_epoch().count());
    if (zret && lat) {
      *lat = std::chrono::system_clock::to_time_t(std::chrono::time_point_cast<std::chrono::system_clock::duration, std::chrono::system_clock>(last));
    }
  }
  return zret;
}

std::time_t
OutboundConnTracker::Group::get_last_alert_epoch_time() const
{
  Time last{Time::duration{Ticker{_last_alert}}}; // Most recent alert time in a time_point.
  return std::chrono::system_clock::to_time_t(std::chrono::time_point_cast<std::chrono::system_clock::duration, std::chrono::system_clock>(Time{Time::duration{Ticker{_last_alert}}}));
}

void
OutboundConnTracker::get(std::vector<Group const*>& groups)
{
  ink_scoped_mutex_lock lock(_imp._mutex); // TABLE LOCK
  auto n = _imp._table.count();
  groups.resize(0);
  groups.reserve(n);
  for (Group const &g : _imp._table) {
    groups.push_back(&g);
  }
}

std::string
OutboundConnTracker::to_json_string()
{
  std::string text;
  size_t extent = 0;
  static const ts::BWFormat header_fmt{R"({{"connectionCountSize": {}, "connectionCountList": [
)"};
  static const ts::BWFormat item_fmt{R"(  {{"ip": "{}", "fqdn": "{}", "type": "{}", "count": {}, "block": {}, "alert": {}}},
)"};
  static const ts::string_view trailer{"]}"};
  static const auto printer = [](ts::BufferWriter& w, Group const* g) -> ts::BufferWriter& {
    w.print(item_fmt, g->_addr, g->_fqdn_hash, g->_match_type, g->_count.load(), g->_blocked.load(), g->get_last_alert_epoch_time());
    return w;
  };
  std::vector<Group const *> groups;

  self_type::get(groups);

  extent += ts::LocalBufferWriter<0>().print(header_fmt, groups.size()).extent();
  for (auto g : groups) {
    ts::FixedBufferWriter fw{nullptr, 0};
    extent += printer(fw, g).extent();
  }
  extent += trailer.size();

  text.resize(extent);
  ts::FixedBufferWriter w(const_cast<char *>(text.data()), text.size());
  w.print(header_fmt, groups.size());
  for (auto g : groups) {
    printer(w,g);
  }
  if (groups.size() > 0 && w.remaining()) {
    w.auxBuffer()[-2] = ' '; // convert trailing comma to space.
  }
  w.write(trailer);
  return text;
}

void
OutboundConnTracker::dump(FILE *f)
{
  std::vector<Group const *> groups;

  self_type::get(groups);

  if (groups.size()) {
    fprintf(f, "\nUpstream Connection Tracking\n%5s | %5s | %24s | %33s | %8s |\n", "Count", "Block", "Address", "Hostname Hash", "Match");
    fprintf(f, "------|-------|--------------------------|-----------------------------------|----------|\n");

    for (Group const* g : groups) {
      ts::LocalBufferWriter<128> w;
      w.print("{:5} | {:5} | {:24} | {:33} | {:8} |", g->_count.load(), g->_blocked.load(), g->_addr, g->_fqdn_hash, g->_match_type);
      fprintf(f, "%.*s\n", static_cast<int>(w.size()), w.data());
    }

    fprintf(f, "------|-------|--------------------------|-----------------------------------|----------|\n");
  }
}

struct ShowConnectionCount : public ShowCont {
  ShowConnectionCount(Continuation *c, HTTPHdr *h) : ShowCont(c, h) { SET_HANDLER(&ShowConnectionCount::showHandler); }
  int showHandler(int event, Event *e)
  {
    CHECK_SHOW(show(OutboundConnTracker::to_json_string().c_str()));
    return completeJson(event, e);
  }
};

Action *
register_ShowConnectionCount(Continuation *c, HTTPHdr *h)
{
  ShowConnectionCount *s = new ShowConnectionCount(c, h);
  this_ethread()->schedule_imm(s);
  return &s->action;
}
