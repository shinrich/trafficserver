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
ts = Test.MakeATSProcess("ts", enable_cache=False)

ts.Disk.records_config.update({'proxy.config.diags.debug.tags': 'http',
                               'proxy.config.diags.debug.enabled': 1
                               })

tr = Test.AddTestRun()
tr.Processes.Default.StartBefore(Test.Processes.ts)
tr.Setup.Copy("requests-nc.sh")
tr.Disk.File(os.path.join(Test.RunDirectory, "test.out"), id="testout")
tr.Processes.Default.Command = "sh -x ./requests-nc.sh {}".format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 1
tr.Processes.Default.Streams.stdout = 'general-connection-failure-502.gold'
