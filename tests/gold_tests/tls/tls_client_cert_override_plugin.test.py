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

Test.Summary = '''
Test conf_remp to specify different client certificates to offer to the origin.  Loading certs/keys via plugin.
'''

import os
import subprocess

ts = Test.MakeATSProcess("ts", command="traffic_manager", select_ports=True)
cafile = "{0}/signer.pem".format(Test.RunDirectory)
cafile2 = "{0}/signer2.pem".format(Test.RunDirectory)
server = Test.MakeOriginServer("server", ssl=True, options = { "--clientCA": cafile, "--clientverify": ""}, clientcert="{0}/signed-foo.pem".format(Test.RunDirectory), clientkey="{0}/signed-foo.key".format(Test.RunDirectory))
server2 = Test.MakeOriginServer("server2", ssl=True, options = { "--clientCA": cafile2, "--clientverify": ""}, clientcert="{0}/signed2-bar.pem".format(Test.RunDirectory), clientkey="{0}/signed-bar.key".format(Test.RunDirectory))
server3 = Test.MakeOriginServer("server3")
server.Setup.Copy("ssl/signer.pem")
server.Setup.Copy("ssl/signer2.pem")
server.Setup.Copy("ssl/signed-foo.pem")
server.Setup.Copy("ssl/signed-foo.key")
server.Setup.Copy("ssl/signed2-foo.pem")
server.Setup.Copy("ssl/signed2-bar.pem")
server.Setup.Copy("ssl/signed-bar.key")
server2.Setup.Copy("ssl/signer.pem")
server2.Setup.Copy("ssl/signer2.pem")
server2.Setup.Copy("ssl/signed-foo.pem")
server2.Setup.Copy("ssl/signed-foo.key")
server2.Setup.Copy("ssl/signed2-foo.pem")
server2.Setup.Copy("ssl/signed2-bar.pem")
server2.Setup.Copy("ssl/signed-bar.key")

request_header = {"headers": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
server.addResponse("sessionlog.json", request_header, response_header)
request_header = {"headers": "GET / HTTP/1.1\r\nHost: bar.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {"headers": "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
server.addResponse("sessionlog.json", request_header, response_header)

ts.addSSLfile("ssl/server.pem")
ts.addSSLfile("ssl/server.key")
ts.addSSLfile("ssl/signed-foo.pem")
ts.addSSLfile("ssl/signed-foo.key")
ts.addSSLfile("ssl/signed2-foo.pem")
ts.addSSLfile("ssl/signed-bar.pem")
ts.addSSLfile("ssl/signed2-bar.pem")
ts.addSSLfile("ssl/signed-bar.key")

ts.Disk.sni_yaml.AddLine('sni:')
ts.Disk.sni_yaml.AddLine('- fqdn: random')
ts.Disk.sni_yaml.AddLine('  verify_server_properties: NONE')
snipath = ts.Disk.sni_yaml.AbsPath

Test.PreparePlugin(os.path.join(Test.Variables.AtsTestToolsDir, 'plugins', 'ssl_secret_load_test.cc'), ts)

ts.Disk.records_config.update({
    'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.client.verify.server':  0,
    'proxy.config.ssl.server.cipher_suite': 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:RC4-SHA:RC4-MD5:AES128-SHA:AES256-SHA:DES-CBC3-SHA!SRP:!DSS:!PSK:!aNULL:!eNULL:!SSLv2',
    'proxy.config.ssl.client.cert.path': '{0}/../'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.client.cert.filename': 'signed-foo.pem',
    'proxy.config.ssl.client.private_key.path': '{0}/../'.format(ts.Variables.SSLDir),
    'proxy.config.ssl.client.private_key.filename': 'signed-foo.key',
    'proxy.config.exec_thread.autoconfig.scale': 1.0,
    'proxy.config.url_remap.pristine_host_hdr' : 1,
})

ts.Disk.ssl_multicert_config.AddLine(
    'dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key'
)

ts.Disk.remap_config.AddLine(
    'map /case1 https://127.0.0.1:{0}/ @plugin=conf_remap.so @pparam=proxy.config.ssl.client.cert.filename={1} plugin=conf_remap.so @pparam=proxy.config.ssl.client.private_key.filename={2}'.format(server.Variables.SSL_Port, "signed-foo.pem", "signed-foo.key")
)
ts.Disk.remap_config.AddLine(
    'map /badcase1 https://127.0.0.1:{0}/ @plugin=conf_remap.so @pparam=proxy.config.ssl.client.cert.filename={1} plugin=conf_remap.so @pparam=proxy.config.ssl.client.private_key.filename={2}'.format(server.Variables.SSL_Port, "signed2-foo.pem", "signed-foo.key")
)
ts.Disk.remap_config.AddLine(
    'map /case2 https://127.0.0.1:{0}/ @plugin=conf_remap.so @pparam=proxy.config.ssl.client.cert.filename={1} plugin=conf_remap.so @pparam=proxy.config.ssl.client.private_key.filename={2}'.format(server2.Variables.SSL_Port, "signed2-foo.pem", "signed-foo.key")
)
ts.Disk.remap_config.AddLine(
    'map /badcase2 https://127.0.0.1:{0}/ @plugin=conf_remap.so @pparam=proxy.config.ssl.client.cert.filename={1} plugin=conf_remap.so @pparam=proxy.config.ssl.client.private_key.filename={2}'.format(server2.Variables.SSL_Port, "signed-foo.pem", "signed-foo.key")
)

# Should succeed
tr = Test.AddTestRun("Connect with correct client cert to first server")
tr.Processes.Default.StartBefore(Test.Processes.ts)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(server2)
tr.StillRunningAfter = ts
tr.StillRunningAfter = server
tr.StillRunningAfter = server2
tr.Processes.Default.Command = "curl -H host:example.com  http://127.0.0.1:{0}/case1".format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ExcludesExpression("Could Not Connect", "Check response")

#Should fail
trfail = Test.AddTestRun("Connect with bad client cert to first server")
trfail.StillRunningAfter = ts
trfail.StillRunningAfter = server
trfail.StillRunningAfter = server2
trfail.Processes.Default.Command = 'curl -H host:example.com  http://127.0.0.1:{0}/badcase1'.format(ts.Variables.port)
trfail.Processes.Default.ReturnCode = 0
trfail.Processes.Default.Streams.stdout = Testers.ContainsExpression("Could Not Connect", "Check response")

# Should succeed
trbar = Test.AddTestRun("Connect with correct client cert to second server")
trbar.StillRunningAfter = ts
trbar.StillRunningAfter = server
trbar.StillRunningAfter = server2
trbar.Processes.Default.Command = "curl -H host:bar.com  http://127.0.0.1:{0}/case2".format(ts.Variables.port)
trbar.Processes.Default.ReturnCode = 0
trbar.Processes.Default.Streams.stdout = Testers.ExcludesExpression("Could Not Connect", "Check response")

#Should fail
trbarfail = Test.AddTestRun("Connect with bad client cert to second server")
trbarfail.StillRunningAfter = ts
trbarfail.StillRunningAfter = server
trbarfail.StillRunningAfter = server2
trbarfail.Processes.Default.Command = 'curl -H host:bar.com  http://127.0.0.1:{0}/badcase2'.format(ts.Variables.port)
trbarfail.Processes.Default.ReturnCode = 0
trbarfail.Processes.Default.Streams.stdout = Testers.ContainsExpression("Could Not Connect", "Check response")

# Test the case of updating certificate contents without changing file name.
trupdate = Test.AddTestRun("Update client cert file in place")
trupdate.StillRunningAfter = ts
trupdate.StillRunningAfter = server
trupdate.StillRunningAfter = server2
# Make a meaningless config change on the path so the records.config reload logic will trigger
trupdate.Setup.CopyAs("ssl/signed2-bar.pem", ".", "{0}/signed-bar.pem".format(ts.Variables.SSLDir))
# in the config/ssl directory for records.config
trupdate.Setup.CopyAs("ssl/signed-foo.pem", ".", "{0}/signed2-foo.pem".format(ts.Variables.SSLDir))
trupdate.Processes.Default.Command = 'traffic_ctl config set proxy.config.ssl.client.cert.path {0}/; touch {1}'.format(ts.Variables.SSLDir,snipath)
# Need to copy over the environment so traffic_ctl knows where to find the unix domain socket
trupdate.Processes.Default.Env = ts.Env
trupdate.Processes.Default.ReturnCode = 0


# Parking this as a ready tester on a meaningless process
# Stall the test runs until the sni reload has completed
# At that point the new sni settings are ready to go
def sni_reload_done(tsenv):
  def done_reload(process, hasRunFor, **kw):
    cmd = "grep 'sni.yaml finished loading' {0} | wc -l > {1}/test.out".format(ts.Disk.diags_log.Name, Test.RunDirectory)
    retval = subprocess.run(cmd, shell=True, env=tsenv)
    if retval.returncode == 0:
      cmd ="if [ -f {0}/test.out -a \"`cat {0}/test.out`\" = \"3\" ] ; then true; else false; fi".format(Test.RunDirectory)
      retval = subprocess.run(cmd, shell = True, env=tsenv)
    return retval.returncode == 0
  return done_reload

tr2reload = Test.AddTestRun("Reload config")
tr2reload.StillRunningAfter = ts
tr2reload.StillRunningAfter = server
tr2reload.StillRunningAfter = server2
tr2reload.Processes.Default.Command = 'traffic_ctl config reload'
# Need to copy over the environment so traffic_ctl knows where to find the unix domain socket
tr2reload.Processes.Default.Env = ts.Env
tr2reload.Processes.Default.ReturnCode = 0

tr3bar = Test.AddTestRun("Make request with other foo.  badcase1 should now work")
# Wait for the reload to complete
tr3bar.Processes.Default.StartBefore(server3, ready=sni_reload_done(ts.Env))
tr3bar.StillRunningAfter = ts
tr3bar.StillRunningAfter = server
tr3bar.StillRunningAfter = server2
tr3bar.Processes.Default.Command = 'curl  -H host:foo.com http://127.0.0.1:{0}/badcase1'.format(ts.Variables.port)
tr3bar.Processes.Default.ReturnCode = 0
tr3bar.Processes.Default.Streams.stdout = Testers.ExcludesExpression("Could Not Connect", "Check response")


