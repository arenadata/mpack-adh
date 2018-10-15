from resource_management.core.resources.system import Execute
from resource_management import *

class arenadata_tools(Script):
    def install(self, env):
        Logger.info("Installing Arenadata Tools packages")
        self.install_packages(env)
        Execute ('ln -s /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.181-3.b13.el7_5.x86_64/jre/lib/amd64/server/libjvm.so /usr/lib64/libjvm.so')
        #if any other install steps were needed they can be added here

    def configure(self,env):
        import params
        env.set_params(params)
        stack_version = get_stack_version('ads-tools')

if __name__ == "__main__":
    arenadata_tools().execute()
