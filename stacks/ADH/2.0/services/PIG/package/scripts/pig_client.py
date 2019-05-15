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

import sys
import os
from resource_management.libraries.script.script import Script
from resource_management.libraries.functions import stack_select
from resource_management.libraries.functions.constants import StackFeature
from resource_management.libraries.functions.stack_features import check_stack_feature
from pig import pig
from ambari_commons import OSConst
from ambari_commons.os_family_impl import OsFamilyFuncImpl, OsFamilyImpl
from resource_management.libraries.functions.default import default
from resource_management.core.exceptions import ClientComponentHasNoStatus
from resource_management.core.resources.system import Execute

class PigClient(Script):
  def configure(self, env):
    import params
    env.set_params(params)
    pig()

  def status(self, env):
    raise ClientComponentHasNoStatus()

@OsFamilyImpl(os_family=OsFamilyImpl.DEFAULT)
class PigClientLinux(PigClient):
  def pre_upgrade_restart(self, env, upgrade_type=None):
    import params
    env.set_params(params)

    if params.version and check_stack_feature(StackFeature.ROLLING_UPGRADE, params.version):
      stack_select.select_packages(params.version)

  def install(self, env):
    self.install_packages(env)
    self.configure(env)
    Execute(('tar', '-czf', '/usr/lib/pig/pig.tar.gz', '-C', '/usr/lib/pig/lib/', '.'), sudo = True)


@OsFamilyImpl(os_family=OSConst.WINSRV_FAMILY)
class PigClientWindows(PigClient):

  def install(self, env):
    import params
    if params.pig_home is None:
      self.install_packages(env)
    self.configure(env)

if __name__ == "__main__":
  PigClient().execute()
