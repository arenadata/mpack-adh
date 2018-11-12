#!/usr/bin/env python

import sys, os, pwd, grp, signal, time, glob
from resource_management.libraries.functions.check_process_status import check_process_status
from resource_management import *
from subprocess import call

class TaskManager(Script):

  def get_component_name(self):
    return "flink"

  def get_env(self):
    import params
    return {'JAVA_HOME': params.java_home, 'FLINK_PID_DIR': params.flink_pid_dir}

  def install(self, env):
    import params
    import status_params

    env.set_params(params)
    env.set_params(status_params)
    self.install_packages(env)

    Directory([status_params.flink_pid_dir, params.flink_log_dir],
            owner=params.flink_user,
            group=params.flink_group
    )

    File(params.flink_log_file,
            mode=0644,
            owner=params.flink_user,
            group=params.flink_group,
            content=''
    )

  def configure(self, env, isInstall=False):
    import params
    import status_params
    env.set_params(params)
    env.set_params(status_params)

    #write out config
    properties_content=InlineTemplate(params.flink_yaml_content)
    File(format("{conf_dir}/flink-conf.yaml"), content=properties_content, owner=params.flink_user)
    Execute(format("ln -sf {flink_log_dir} {flink_install_dir}/log"))

  def stop(self, env):
    import params
    import status_params
    cmd = format("{params.bin_dir}/taskmanager.sh stop")
    Execute (cmd, user=params.flink_user, environment=self.get_env())
    File(status_params.flink_task_pid_file,
      action = "delete",
      owner = params.flink_user
    )

  def start(self, env):
    import params
    import status_params

    env.set_params(params)
    env.set_params(status_params)

    self.configure(env, True)

    cmd = format("{params.bin_dir}/taskmanager.sh start >> {params.flink_log_file}")
    #cmd = "env >/tmp/1.log"
    Execute (cmd, user=params.flink_user, environment=self.get_env())

    if os.path.exists(params.temp_file):
      os.remove(params.temp_file)

  def status(self, env):
    import status_params
    check_process_status(status_params.flink_task_pid_file)

if __name__ == "__main__":
  TaskManager().execute()
