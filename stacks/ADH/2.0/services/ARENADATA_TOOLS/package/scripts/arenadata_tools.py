from resource_management.core.resources.system import Execute
from resource_management import *
from resource_management.core.resources.system import Execute

class arenadata_tools(Script):
    def install(self, env):
        Logger.info("Installing Arenadata Tools packages")
        self.install_packages(env)
        #if any other install steps were needed they can be added here
        Execute ('ln -sf /usr/lib/jvm/jre/lib/amd64/server/libjvm.so /usr/lib64/libjvm.so')

    def configure(self,env):
        import params
        env.set_params(params)
        stack_version = get_stack_version('ads-tools')

if __name__ == "__main__":
    arenadata_tools().execute()
