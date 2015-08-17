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

.PHONY: test clean update

MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CURRENT_DIR := $(dir $(MKFILE_PATH))
VIRTUALENV_DIR = $(CURRENT_DIR)/virtualenv
LD_LIBRARY_PATH = /home/y/lib64:/home/y/libexec64:$(LD_LIBARY_PATH)

# Run all tests.
test: $(VIRTUALENV_DIR)
	@source $(VIRTUALENV_DIR)/bin/activate && $(VIRTUALENV_DIR)/bin/nosetests -sv --logging-level=INFO --with-xunit

# Scan and list the tests.
list: $(VIRTUALENV_DIR)
	@source $(VIRTUALENV_DIR)/bin/activate && $(VIRTUALENV_DIR)/bin/nosetests -v --collect-only

# Construct the virtualenv.
$(VIRTUALENV_DIR):
	@if [ ! -d $(VIRTUALENV_DIR) ]; then\
		/opt/python/bin/virtualenv --python=/opt/python/bin/python $(VIRTUALENV_DIR);\
	fi
	@# Update the virtualenv with your dep libraries
	source $(VIRTUALENV_DIR)/bin/activate && $(VIRTUALENV_DIR)/bin/pip install -r $(CURRENT_DIR)/requirements.txt
	@echo "Virtualenv ready!"

# Update the virtualenv with the latest TSQA package and dependencies.
update: $(VIRTUALENV_DIR)
	source $(VIRTUALENV_DIR)/bin/activate && $(VIRTUALENV_DIR)/bin/pip install --upgrade -r $(CURRENT_DIR)/requirements.txt

clean:
	rm -rf virtualenv
