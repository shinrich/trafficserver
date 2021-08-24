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

Test.Summary = '''
Test unsupported values for chunked_encoding
'''

Test.ContinueOnFail = True

# Define default ATS
ts = Test.MakeATSProcess("ts1", select_ports=True, enable_tls=False)
server = Test.MakeOriginServer("server")

testName = ""
request_header = {"headers": "POST /case1 HTTP/1.1\r\nHost: www.example.com\r\nuuid:1\r\n\r\n",
                  "timestamp": "1469733493.993",
                  "body": "stuff"
                  }
response_header = {"headers": "HTTP/1.1 200 OK\r\nServer: uServer\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n",
                   "timestamp": "1469733493.993",
                   "body": "more stuff"}

server.addResponse("sessionlog.json", request_header, response_header)

ts.Disk.records_config.update({'proxy.config.diags.debug.enabled': 0,
                               'proxy.config.diags.debug.tags': 'http'})

ts.Disk.remap_config.AddLine(
    'map / http://127.0.0.1:{0}'.format(server.Variables.Port)
)

# HTTP1.1 POST: www.example.com/case1 with gzip transfer-encoding
tr = Test.AddTestRun()
tr.TimeOut = 5
tr.Processes.Default.Command = 'curl -H "host: example.com" -H "transfer-encoding: gzip" -d "stuff" http://127.0.0.1:{0}/case1  --verbose'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Streams.All = Testers.ContainsExpression("501 Field not implemented", "Should fail")
tr.Processes.Default.Streams.All = Testers.ExcludesExpression("200 OK", "Should not succeed")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts

# HTTP1.1 POST: www.example.com/case1 with gzip and chunked transfer-encoding
tr = Test.AddTestRun()
tr.TimeOut = 5
tr.Processes.Default.Command = 'curl -H "host: example.com" -H "transfer-encoding: gzip" -H "transfer-encoding: chunked" -d "stuff" http://127.0.0.1:{0}/case1  --verbose'.format(
    ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.All = Testers.ContainsExpression("501 Field not implemented", "Should fail")
tr.Processes.Default.Streams.All = Testers.ExcludesExpression("200 OK", "Should not succeed")
tr.StillRunningAfter = server
tr.StillRunningAfter = ts


class MalformedChunkHeaderTest:
    chunkedReplayFile = "replays/malformed_chunked_header.replay.yaml"

    def __init__(self):
        self.setupOriginServer()
        self.setupTS()

    def setupOriginServer(self):
        self.server = Test.MakeVerifierServerProcess("verifier-server", self.chunkedReplayFile)

    def setupTS(self):
        self.ts = Test.MakeATSProcess("ts2", enable_tls=True, enable_cache=False)
        self.ts.addDefaultSSLFiles()
        self.ts.Disk.records_config.update({
            "proxy.config.diags.debug.enabled": 1,
            "proxy.config.diags.debug.tags": "http",
            "proxy.config.ssl.server.cert.path": f'{self.ts.Variables.SSLDir}',
            "proxy.config.ssl.server.private_key.path": f'{self.ts.Variables.SSLDir}',
            "proxy.config.ssl.client.verify.server.policy": 'PERMISSIVE',
        })
        self.ts.Disk.ssl_multicert_config.AddLine(
            'dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key'
        )
        self.ts.Disk.remap_config.AddLine(
            f"map / http://127.0.0.1:{self.server.Variables.http_port}/",
        )

    def runChunkedTraffic(self):
        tr = Test.AddTestRun()
        tr.AddVerifierClientProcess(
            "client",
            self.chunkedReplayFile,
            http_ports=[self.ts.Variables.port],
            https_ports=[self.ts.Variables.ssl_port],
            other_args='--thread-limit 1')
        tr.Processes.Default.StartBefore(self.server)
        tr.Processes.Default.StartBefore(self.ts)
        tr.StillRunningAfter = self.server
        tr.StillRunningAfter = self.ts

    def run(self):
        self.runChunkedTraffic()


MalformedChunkHeaderTest().run()
