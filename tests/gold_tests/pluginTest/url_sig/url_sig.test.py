'''
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
import subprocess
Test.Summary = '''
Test url_sig plugin
'''

# Skip if plugins not present.
Test.SkipUnless(Condition.PluginExists('url_sig.so'))
Test.SkipUnless(Condition.PluginExists('balancer.so'))

# Set up to check the output after the tests have run.
#
url_sig_log_id = Test.Disk.File("url_sig.log")
url_sig_log_id.Content = "url_sig.gold"

# Define default ATS
ts = Test.MakeATSProcess("ts")

server = Test.MakeOriginServer("server",  options={'--load': os.path.join(Test.TestDirectory, 'url_sig_observer.py')})

request_header = {"headers": "GET /foo HTTP/1.1\r\nHost: just.any.thing\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
# expected response from the origin server
response_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
# add response to the server dictionary
server.addResponse("sessionfile.log", request_header, response_header)

# ts.Disk.records_config.update({
#     'proxy.config.diags.debug.enabled': 1,
#     'proxy.config.diags.debug.tags': 'http|url_sig'
# })

ts.Disk.remap_config.AddLine(
    'map http://one.two.three/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
    ' @plugin=url_sig.so @pparam={}/url_sig.config'.format(Test.TestDirectory)
)
ts.Disk.remap_config.AddLine(
    'map http://four.five.six/ http://127.0.0.1:{}/'.format(server.Variables.Port) +
    ' @plugin=url_sig.so @pparam={}/url_sig.config @pparam=pristineurl'.format(Test.TestDirectory)
)
ts.Disk.remap_config.AddLine(
    'map http://seven.eight.nine/ http://dummy' +
    ' @plugin=balancer.so @pparam=--policy=hash,url @pparam=127.0.0.1:{}'.format(server.Variables.Port) +
    ' @plugin=url_sig.so @pparam={}/url_sig.config @pparam=PristineUrl'.format(Test.TestDirectory)
)

# Ask the OS if the port is ready for connect()
#
def CheckPort(Port):
    return lambda: 0 == subprocess.call('netstat --listen --tcp -n | grep -q :{}'.format(Port), shell=True)

# Validation failure tests.

tr = Test.AddTestRun()
tr.Processes.Default.StartBefore(ts, ready=CheckPort(ts.Variables.port))
tr.Processes.Default.StartBefore(server, ready=CheckPort(server.Variables.Port))
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Command = (
    "curl --verbose --proxy http://127.0.0.1:{} 'http://four.five.six/".format(ts.Variables.port) +
    "foo?C=127.0.0.1'"
)

tr = Test.AddTestRun()
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Command = (
    "curl --verbose --proxy http://127.0.0.1:{} 'http://one.two.three/".format(ts.Variables.port) +
    "foo?'"
)

tr = Test.AddTestRun()
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Command = (
    "curl --verbose --proxy http://127.0.0.1:{} 'http://one.two.three/".format(ts.Variables.port) +
    "foo'"
)

tr = Test.AddTestRun()
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Command = (
    "curl --verbose --proxy http://127.0.0.1:{} 'http://one.two.three/".format(ts.Variables.port) +
    "foo?E=33046185365&A=1&K=7&P=1'"
)

# Success tests.

# No client / SHA1 / P=1 / URL not pristine / URL not altered.
#
tr = Test.AddTestRun()
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Command = (
    "curl --verbose --proxy http://127.0.0.1:{} 'http://one.two.three/".format(ts.Variables.port) +
    "foo?E=33046185365&A=1&K=7&P=1&S=e6873a53ea6a005ec3f5edf1c1097f65f49f24aa'"
)

# With client / SHA1 / P=1 / URL pristine / URL not altered.
#
tr = Test.AddTestRun()
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Command = (
    "curl --verbose --proxy http://127.0.0.1:{} 'http://four.five.six/".format(ts.Variables.port) +
    "foo?C=127.0.0.1&E=33046249868&A=1&K=13&P=1&S=7056d3786828b7b46a214d1e97ad448addd4b3ce'"
)

# With client / SHA1 / P=1 / URL pristine / URL altered.
#
tr = Test.AddTestRun()
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Command = (
    "curl --verbose --proxy http://127.0.0.1:{} 'http://seven.eight.nine/".format(ts.Variables.port) +
    "foo?E=33046258055&A=2&K=0&P=1&S=5b718279976f0c0b3ce0f84c472cf4de'"
)
