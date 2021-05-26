'''
Verify that request following a ill-formed request is not processed
'''
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

import os

Test.Summary = '''
Verify that request following a ill-formed request is not processed
'''
ts = Test.MakeATSProcess("ts", enable_cache=True)

ts.Disk.records_config.update({'proxy.config.diags.debug.tags': 'http',
                               'proxy.config.diags.debug.enabled': 1
                               })

server = Test.MakeOriginServer("server")
request_header = {"headers": "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nLast-Modified: Tue, 08 May 2018 15:49:41 GMT\r\nCache-Control: max-age=1000\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "xxx"}
server.addResponse("sessionlog.json", request_header, response_header)

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}'.format(server.Variables.Port)
)

# Make a good request to get item in the cache for later tests
tr = Test.AddTestRun("Good control")
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(Test.Processes.ts)
tr.Processes.Default.Command = 'printf "GET / HTTP/1.1\r\nHost: bob\r\n\r\n" | nc  127.0.0.1 {}'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0

# Space after header name
tr = Test.AddTestRun("space after header name")
tr.Processes.Default.Command = 'printf "GET /foo HTTP/1.1\r\nHost : bob\r\n\r\nGET / HTTP/1.1\r\nHost: boa\r\n\r\n" | nc  127.0.0.1 {}'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = 'gold/bad_good_request.gold'

# invalid version number
tr = Test.AddTestRun("Invalid protocol version number")
tr.Processes.Default.Command = 'printf "GET / HTTP/1.9\r\nHost:bob\r\n\r\nGET / HTTP/1.1\r\nHost: boa\r\n\r\n" | nc  127.0.0.1 {}'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = 'gold/bad_protocol_number.gold'

# mangled termination
tr = Test.AddTestRun("mangled line termination")
tr.Processes.Default.Command = 'printf "GET / HTTP/1.1\r\nHost:bob\r\n \r\nGET / HTTP/1.1\r\nHost: boa\r\n\r\n" | nc  127.0.0.1 {}'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = 'gold/bad_good_request.gold'

# Weird character in transfer-encoding value.  Correctly returns error, but does not close connection
tr = Test.AddTestRun("Bad transfer-encoding value")
tr.Processes.Default.Command = 'printf "GET /foo HTTP/1.1\r\nHost: bob\r\nTransfer-Encoding: \\\"chunked\\\"\r\n\r\nGET / HTTP/1.1\r\nHost: boa\r\n\r\n" | nc  127.0.0.1 {}'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = 'gold/bad_te_value.gold'

# Space before header name; Does not fail.  Returns 200 response;  But it eliminates the host header on parsing in.
tr = Test.AddTestRun("space before header name")
tr.Processes.Default.Command = 'printf "GET /foo HTTP/1.1\r\n Host: bob\r\n\r\nGET / HTTP/1.1\r\nHost: boa\r\n\r\n" | nc  127.0.0.1 {}'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = 'gold/bad_good_request.gold'

# Make the protocol string bad
# ATS parses as GET / H HTTP/1.1, passes along which makes microserver sad
tr = Test.AddTestRun("bad protocol string")
tr.Processes.Default.Command = 'printf "GET / HhTTP/1.1\r\nHost:bob\r\n\r\nGET / HTTP/1.1\r\nHost: boa\r\n\r\n" | nc  127.0.0.1 {}'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = 'gold/bad_protocol_number.gold'

# Mixed case method name;  Should fail but ATS is treating gET as GET
tr = Test.AddTestRun("mixed case method")
tr.Processes.Default.Command = 'printf "gET / HTTP/1.1\r\nHost:bob\r\n\r\nGET / HTTP/1.1\r\nHost: boa\r\n\r\n" | nc  127.0.0.1 {}'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 1
tr.Processes.Default.Streams.stdout = 'bad_good_request.gold'

# Weird character in content-length value.  Looks like we still need to apply the patch
tr = Test.AddTestRun("weird character in content length")
tr.Processes.Default.Command = 'printf "GET /foo HTTP/1.1\r\nHost: bob\r\nContent-length: +7\r\n\r\nGET / HTTP/1.1\r\nHost: boa\r\n\r\n" | nc  127.0.0.1 {}'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = 'gold/bad_good_request.gold'
