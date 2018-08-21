from resource_management import *

class arenadata_tools(Script):
    def install(self, env):
        Logger.info("Installing Arenadata Tools packages")
        self.install_packages(env)
        #if any other install steps were needed they can be added here

    def configure(self,env):
        import params
        env.set_params(params)
        stack_version = get_stack_version('ads-tools')

if __name__ == "__main__":
    arenadata_tools().execute()
