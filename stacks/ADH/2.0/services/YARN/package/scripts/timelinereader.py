"""
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

Ambari Agent

"""
import os

from resource_management.libraries.script.script import Script
from resource_management.libraries.functions import stack_select
from resource_management.libraries.functions.constants import StackFeature
from resource_management.libraries.functions.stack_features import check_stack_feature
from resource_management.libraries.functions import check_process_status
from resource_management.libraries.functions.security_commons import build_expectations, \
  cached_kinit_executor, get_params_from_filesystem, validate_security_config_properties,\
  FILE_TYPE_XML
from resource_management.libraries.functions.format import format
from resource_management.core.logger import Logger
from resource_management.core.resources.system import Execute

from yarn import yarn
from service import service
from ambari_commons import OSConst
from ambari_commons.os_family_impl import OsFamilyImpl
from hbase_service import hbase, configure_hbase


class ApplicationTimelineReader(Script):
  def install(self, env):
    self.install_packages(env)

  def start(self, env, upgrade_type=None):
    import params
    env.set_params(params)
    self.configure(env) # FOR SECURITY
    if not params.is_hbase_system_service_launch:
       hbase(action='start')
    service('timelinereader', action='start')

  def stop(self, env, upgrade_type=None):
    import params
    env.set_params(params)
    if not params.is_hbase_system_service_launch:
       hbase(action='stop')
    service('timelinereader', action='stop')

  def configure(self, env, action = None):
    import params
    env.set_params(params)
    yarn(name='apptimelinereader')
    if not params.is_hbase_system_service_launch:
       configure_hbase(env)

@OsFamilyImpl(os_family=OSConst.WINSRV_FAMILY)
class ApplicationTimelineReaderWindows(ApplicationTimelineReader):
  def status(self, env):
    service('timelinereader', action='status')


@OsFamilyImpl(os_family=OsFamilyImpl.DEFAULT)
class ApplicationTimelineReaderDefault(ApplicationTimelineReader):
  def pre_upgrade_restart(self, env, upgrade_type=None):
    Logger.info("Executing Stack Upgrade pre-restart")
    import params
    env.set_params(params)

    if params.version and check_stack_feature(StackFeature.ROLLING_UPGRADE, params.version):
      stack_select.select_packages(params.version)

  def status(self, env):
    import status_params
    env.set_params(status_params)
    for pid_file in self.get_pid_files():
      check_process_status(pid_file)

  def get_log_folder(self):
    import params
    return params.yarn_log_dir

  def get_user(self):
    import params
    return params.yarn_user

  def get_pid_files(self):
    import params
    pid_files = []
    pid_files.append(format("{yarn_timelinereader_pid_file}"))
    if not params.is_hbase_system_service_launch:
       pid_files.append(format("{yarn_hbase_pid_dir}/hbase-{yarn_hbase_user}-master.pid"))
       pid_files.append(format("{yarn_hbase_pid_dir}/hbase-{yarn_hbase_user}-regionserver.pid"))
    return pid_files

if __name__ == "__main__":
  ApplicationTimelineReader().execute()
