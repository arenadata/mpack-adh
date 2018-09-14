#!/usr/bin/env python
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

"""
import os
import sys

from ambari_commons import OSCheck
from resource_management import get_bare_principal
from resource_management.libraries.functions.version import format_stack_version
from resource_management.libraries.script.script import Script
from resource_management.libraries.functions.format import format
from resource_management.libraries.functions.default import default
import status_params
from resource_management.libraries.resources.hdfs_resource import HdfsResource
# Local Imports
from status_params import *
from resource_management.libraries.functions.stack_features import check_stack_feature
from resource_management.libraries.functions import StackFeature
from resource_management.libraries.functions.is_empty import is_empty
from resource_management.libraries.functions.expect import expect
from resource_management.libraries.functions.setup_ranger_plugin_xml import generate_ranger_service_config
from resource_management.libraries.functions.get_not_managed_resources import get_not_managed_resources

def configs_for_ha(atlas_hosts, metadata_port, is_atlas_ha_enabled, metadata_protocol):
  """
  Return a dictionary of additional configs to merge if Atlas HA is enabled.
  :param atlas_hosts: List of hostnames that contain Atlas
  :param metadata_port: Port number
  :param is_atlas_ha_enabled: None, True, or False
  :param metadata_protocol: http or https
  :return: Dictionary with additional configs to merge to application-properties if HA is enabled.
  """
  additional_props = {}
  if atlas_hosts is None or len(atlas_hosts) == 0 or metadata_port is None:
    return additional_props

  # Sort to guarantee each host sees the same values, assuming restarted at the same time.
  atlas_hosts = sorted(atlas_hosts)

  # E.g., id1,id2,id3,...,idn
  _server_id_list = ["id" + str(i) for i in range(1, len(atlas_hosts) + 1)]
  atlas_server_ids = ",".join(_server_id_list)
  additional_props["atlas.server.ids"] = atlas_server_ids

  i = 0
  for curr_hostname in atlas_hosts:
    id = _server_id_list[i]
    prop_name = "atlas.server.address." + id
    prop_value = curr_hostname + ":" + metadata_port
    additional_props[prop_name] = prop_value
    if "atlas.rest.address" in additional_props:
      additional_props["atlas.rest.address"] += "," + metadata_protocol + "://" + prop_value
    else:
      additional_props["atlas.rest.address"] = metadata_protocol + "://" + prop_value

    i += 1

  # This may override the existing property
  if i == 1 or (i > 1 and is_atlas_ha_enabled is False):
    additional_props["atlas.server.ha.enabled"] = "false"
  elif i > 1:
    additional_props["atlas.server.ha.enabled"] = "true"

  return additional_props
  
# server configurations
config = Script.get_config()
exec_tmp_dir = Script.get_tmp_dir()
stack_root = Script.get_stack_root()

# Needed since this is an Atlas Hook service.
cluster_name = config['clusterName']

java_version = expect("/ambariLevelParams/java_version", int)

zk_root = default('/configurations/application-properties/atlas.server.ha.zookeeper.zkroot', '/apache_atlas')
stack_supports_zk_security = check_stack_feature(StackFeature.SECURE_ZOOKEEPER, version_for_stack_feature_checks)
atlas_kafka_group_id = default('/configurations/application-properties/atlas.kafka.hook.group.id', None)

if security_enabled:
  _hostname_lowercase = config['agentLevelParams']['hostname'].lower()
  _atlas_principal_name = config['configurations']['application-properties']['atlas.authentication.principal']
  atlas_jaas_principal = _atlas_principal_name.replace('_HOST',_hostname_lowercase)
  atlas_keytab_path = config['configurations']['application-properties']['atlas.authentication.keytab']

# New Cluster Stack Version that is defined during the RESTART of a Stack Upgrade
version = default("/commandParams/version", None)

# stack version
stack_version_unformatted = config['clusterLevelParams']['stack_version']
stack_version_formatted = format_stack_version(stack_version_unformatted)

metadata_home = format('{stack_root}/current/atlas-server')
metadata_bin = format("{metadata_home}/bin")

python_binary = os.environ['PYTHON_EXE'] if 'PYTHON_EXE' in os.environ else sys.executable
metadata_start_script = format("{metadata_bin}/atlas_start.py")
metadata_stop_script = format("{metadata_bin}/atlas_stop.py")

# metadata local directory structure
log_dir = config['configurations']['atlas-env']['metadata_log_dir']

# service locations
hadoop_conf_dir = os.path.join(os.environ["HADOOP_HOME"], "conf") if 'HADOOP_HOME' in os.environ else '/etc/hadoop/conf'

# some commands may need to supply the JAAS location when running as atlas
atlas_jaas_file = format("{conf_dir}/atlas_jaas.conf")

# user
user_group = config['configurations']['cluster-env']['user_group']

# metadata env
java64_home = config['ambariLevelParams']['java_home']
java_exec = format("{java64_home}/bin/java")
env_sh_template = config['configurations']['atlas-env']['content']

# credential provider
credential_provider = format( "jceks://file@{conf_dir}/atlas-site.jceks")

# command line args
ssl_enabled = default("/configurations/application-properties/atlas.enableTLS", False)
http_port = default("/configurations/application-properties/atlas.server.http.port", "21000")
https_port = default("/configurations/application-properties/atlas.server.https.port", "21443")
if ssl_enabled:
  metadata_port = https_port
  metadata_protocol = 'https'
else:
  metadata_port = http_port
  metadata_protocol = 'http'

metadata_host = config['agentLevelParams']['hostname']

atlas_hosts = sorted(default('/clusterHostInfo/atlas_server_hosts', []))
metadata_server_host = atlas_hosts[0] if len(atlas_hosts) > 0 else "UNKNOWN_HOST"

# application properties
application_properties = dict(config['configurations']['application-properties'])
# Depending on user configured value for atlas.server.bind.address
# we need to populate the value in atlas-application.properties
metadata_host_bind_address_value = default('/configurations/application-properties/atlas.server.bind.address','0.0.0.0')
if metadata_host_bind_address_value == '0.0.0.0':
  application_properties["atlas.server.bind.address"] = '0.0.0.0'
elif metadata_host_bind_address_value == 'localhost':
  application_properties["atlas.server.bind.address"] = metadata_host
else:
  application_properties["atlas.server.bind.address"] = metadata_host_bind_address_value

# trimming knox_key
if 'atlas.sso.knox.publicKey' in application_properties:
  knox_key = application_properties['atlas.sso.knox.publicKey']
  knox_key_without_new_line = knox_key.replace("\n","")
  application_properties['atlas.sso.knox.publicKey'] = knox_key_without_new_line

if check_stack_feature(StackFeature.ATLAS_UPGRADE_SUPPORT, version_for_stack_feature_checks):
  metadata_server_url = application_properties["atlas.rest.address"]
else:
  # In HDP 2.3 and 2.4 the property was computed and saved to the local config but did not exist in the database.
  metadata_server_url = format('{metadata_protocol}://{metadata_server_host}:{metadata_port}')
  application_properties["atlas.rest.address"] = metadata_server_url

# Atlas HA should populate
# atlas.server.ids = id1,id2,...,idn
# atlas.server.address.id# = host#:port
# User should not have to modify this property, but still allow overriding it to False if multiple Atlas servers exist
# This can be None, True, or False
is_atlas_ha_enabled = default("/configurations/application-properties/atlas.server.ha.enabled", None)
additional_ha_props = configs_for_ha(atlas_hosts, metadata_port, is_atlas_ha_enabled, metadata_protocol)
for k,v in additional_ha_props.iteritems():
  application_properties[k] = v


metadata_env_content = config['configurations']['atlas-env']['content']

metadata_opts = config['configurations']['atlas-env']['metadata_opts']
metadata_classpath = config['configurations']['atlas-env']['metadata_classpath']
data_dir = format("{stack_root}/current/atlas-server/data")
expanded_war_dir = os.environ['METADATA_EXPANDED_WEBAPP_DIR'] if 'METADATA_EXPANDED_WEBAPP_DIR' in os.environ else format("{stack_root}/current/atlas-server/server/webapp")

metadata_log4j_content = config['configurations']['atlas-log4j']['content']

metadata_solrconfig_content = default("/configurations/atlas-solrconfig/content", None)

atlas_log_level = config['configurations']['atlas-log4j']['atlas_log_level']
audit_log_level = config['configurations']['atlas-log4j']['audit_log_level']
atlas_log_max_backup_size = default("/configurations/atlas-log4j/atlas_log_max_backup_size", 256)
atlas_log_number_of_backup_files = default("/configurations/atlas-log4j/atlas_log_number_of_backup_files", 20)

# smoke test
smoke_test_user = config['configurations']['cluster-env']['smokeuser']
smoke_test_password = 'smoke'
smokeuser_principal =  config['configurations']['cluster-env']['smokeuser_principal_name']
smokeuser_keytab = config['configurations']['cluster-env']['smokeuser_keytab']


security_check_status_file = format('{log_dir}/security_check.status')

# hbase
hbase_conf_dir = default('configurations/atlas-env/atlas.hbase.conf.dir','/etc/hbase/conf')

atlas_search_backend = default("/configurations/application-properties/atlas.graph.index.search.backend", "solr")
search_backend_solr = atlas_search_backend.startswith('solr')

# infra solr
infra_solr_znode = default("/configurations/infra-solr-env/infra_solr_znode", None)
infra_solr_hosts = default("/clusterHostInfo/infra_solr_hosts", [])
infra_solr_replication_factor = 2 if len(infra_solr_hosts) > 1 else 1
if 'atlas_solr_replication_factor' in config['configurations']['atlas-env']:
  infra_solr_replication_factor = int(default("/configurations/atlas-env/atlas_solr_replication_factor", 1))
atlas_solr_shards = default("/configurations/atlas-env/atlas_solr_shards", 1)
has_infra_solr = len(infra_solr_hosts) > 0
infra_solr_role_atlas = default('configurations/infra-solr-security-json/infra_solr_role_atlas', 'atlas_user')
infra_solr_role_dev = default('configurations/infra-solr-security-json/infra_solr_role_dev', 'dev')
infra_solr_role_ranger_audit = default('configurations/infra-solr-security-json/infra_solr_role_ranger_audit', 'ranger_audit_user')

# zookeeper
zookeeper_hosts = config['clusterHostInfo']['zookeeper_server_hosts']
zookeeper_port = default('/configurations/zoo.cfg/clientPort', None)

# get comma separated lists of zookeeper hosts from clusterHostInfo
index = 0
zookeeper_quorum = ""
for host in zookeeper_hosts:
  zookeeper_host = host
  if zookeeper_port is not None:
    zookeeper_host = host + ":" + str(zookeeper_port)

  zookeeper_quorum += zookeeper_host
  index += 1
  if index < len(zookeeper_hosts):
    zookeeper_quorum += ","

stack_supports_atlas_hdfs_site_on_namenode_ha = check_stack_feature(StackFeature.ATLAS_HDFS_SITE_ON_NAMENODE_HA, version_for_stack_feature_checks)
stack_supports_atlas_core_site = check_stack_feature(StackFeature.ATLAS_CORE_SITE_SUPPORT,version_for_stack_feature_checks)
atlas_server_xmx = default("configurations/atlas-env/atlas_server_xmx", 2048)
atlas_server_max_new_size = default("configurations/atlas-env/atlas_server_max_new_size", 614)

hbase_master_hosts = default('/clusterHostInfo/hbase_master_hosts', [])
has_hbase_master = not len(hbase_master_hosts) == 0

atlas_hbase_setup = format("{exec_tmp_dir}/atlas_hbase_setup.rb")
atlas_kafka_setup = format("{exec_tmp_dir}/atlas_kafka_acl.sh")
atlas_graph_storage_hbase_table = default('/configurations/application-properties/atlas.graph.storage.hbase.table', None)
atlas_audit_hbase_tablename = default('/configurations/application-properties/atlas.audit.hbase.tablename', None)

hbase_user_keytab = default('/configurations/hbase-env/hbase_user_keytab', None)
hbase_principal_name = default('/configurations/hbase-env/hbase_principal_name', None)

# ToDo: Kafka port to Atlas
# Used while upgrading the stack in a kerberized cluster and running kafka-acls.sh
hosts_with_kafka = default('/clusterHostInfo/kafka_broker_hosts', [])
host_with_kafka = hostname in hosts_with_kafka

ranger_tagsync_hosts = default("/clusterHostInfo/ranger_tagsync_hosts", [])
has_ranger_tagsync = len(ranger_tagsync_hosts) > 0
rangertagsync_user = "rangertagsync"

kafka_keytab = default('/configurations/kafka-env/kafka_keytab', None)
kafka_principal_name = default('/configurations/kafka-env/kafka_principal_name', None)
default_replication_factor = default('/configurations/application-properties/atlas.notification.replicas', None)

if check_stack_feature(StackFeature.ATLAS_UPGRADE_SUPPORT, version_for_stack_feature_checks):
  default_replication_factor = default('/configurations/application-properties/atlas.notification.replicas', None)

  kafka_env_sh_template = config['configurations']['kafka-env']['content']
  kafka_home = os.path.join(stack_root,  "current", "kafka-broker")
  kafka_conf_dir = os.path.join(kafka_home, "config")

  kafka_zk_endpoint = default("/configurations/kafka-broker/zookeeper.connect", None)
  kafka_kerberos_enabled = (('security.inter.broker.protocol' in config['configurations']['kafka-broker']) and
                            ((config['configurations']['kafka-broker']['security.inter.broker.protocol'] == "PLAINTEXTSASL") or
                             (config['configurations']['kafka-broker']['security.inter.broker.protocol'] == "SASL_PLAINTEXT")))
  if security_enabled and stack_version_formatted != "" and 'kafka_principal_name' in config['configurations']['kafka-env'] \
    and check_stack_feature(StackFeature.KAFKA_KERBEROS, stack_version_formatted):
    _hostname_lowercase = config['agentLevelParams']['hostname'].lower()
    _kafka_principal_name = config['configurations']['kafka-env']['kafka_principal_name']
    kafka_jaas_principal = _kafka_principal_name.replace('_HOST', _hostname_lowercase)
    kafka_keytab_path = config['configurations']['kafka-env']['kafka_keytab']
    kafka_bare_jaas_principal = get_bare_principal(_kafka_principal_name)
    kafka_kerberos_params = "-Djava.security.auth.login.config={0}/kafka_jaas.conf".format(kafka_conf_dir)
  else:
    kafka_kerberos_params = ''
    kafka_jaas_principal = None
    kafka_keytab_path = None

namenode_host = set(default("/clusterHostInfo/namenode_hosts", []))
has_namenode = not len(namenode_host) == 0

upgrade_direction = default("/commandParams/upgrade_direction", None)
# ranger altas plugin section start

# ranger host
ranger_admin_hosts = default("/clusterHostInfo/ranger_admin_hosts", [])
has_ranger_admin = not len(ranger_admin_hosts) == 0

retry_enabled = default("/commandParams/command_retry_enabled", False)

stack_supports_atlas_ranger_plugin = check_stack_feature(StackFeature.ATLAS_RANGER_PLUGIN_SUPPORT, version_for_stack_feature_checks)
stack_supports_ranger_kerberos = check_stack_feature(StackFeature.RANGER_KERBEROS_SUPPORT, version_for_stack_feature_checks)

# ranger support xml_configuration flag, instead of depending on ranger xml_configurations_supported/ranger-env, using stack feature
xml_configurations_supported = check_stack_feature(StackFeature.RANGER_XML_CONFIGURATION, version_for_stack_feature_checks)

# ranger atlas plugin enabled property
enable_ranger_atlas = default("/configurations/ranger-atlas-plugin-properties/ranger-atlas-plugin-enabled", "No")
enable_ranger_atlas = True if enable_ranger_atlas.lower() == "yes" else False

# ranger hbase plugin enabled property
enable_ranger_hbase = default("/configurations/ranger-hbase-plugin-properties/ranger-hbase-plugin-enabled", "No")
enable_ranger_hbase = True if enable_ranger_hbase.lower() == 'yes' else False

if stack_supports_atlas_ranger_plugin and enable_ranger_atlas:
  # for create_hdfs_directory
  hdfs_user = config['configurations']['hadoop-env']['hdfs_user'] if has_namenode else None
  hdfs_user_keytab = config['configurations']['hadoop-env']['hdfs_user_keytab']  if has_namenode else None
  hdfs_principal_name = config['configurations']['hadoop-env']['hdfs_principal_name'] if has_namenode else None
  hdfs_site = config['configurations']['hdfs-site']
  default_fs = config['configurations']['core-site']['fs.defaultFS']
  dfs_type = default("/clusterLevelParams/dfs_type", "")

  import functools
  from resource_management.libraries.resources.hdfs_resource import HdfsResource
  from resource_management.libraries.functions.get_not_managed_resources import get_not_managed_resources
  #create partial functions with common arguments for every HdfsResource call
  #to create hdfs directory we need to call params.HdfsResource in code

  HdfsResource = functools.partial(
    HdfsResource,
    user = hdfs_user,
    hdfs_resource_ignore_file = "/var/lib/ambari-agent/data/.hdfs_resource_ignore",
    security_enabled = security_enabled,
    keytab = hdfs_user_keytab,
    kinit_path_local = kinit_path_local,
    hadoop_bin_dir = hadoop_bin_dir,
    hadoop_conf_dir = hadoop_conf_dir,
    principal_name = hdfs_principal_name,
    hdfs_site = hdfs_site,
    default_fs = default_fs,
    immutable_paths = get_not_managed_resources(),
    dfs_type = dfs_type
  )

  # ranger atlas service/repository name
  repo_name = str(config['clusterName']) + '_atlas'
  repo_name_value = config['configurations']['ranger-atlas-security']['ranger.plugin.atlas.service.name']
  if not is_empty(repo_name_value) and repo_name_value != "{{repo_name}}":
    repo_name = repo_name_value

  ssl_keystore_password = config['configurations']['ranger-atlas-policymgr-ssl']['xasecure.policymgr.clientssl.keystore.password']
  ssl_truststore_password = config['configurations']['ranger-atlas-policymgr-ssl']['xasecure.policymgr.clientssl.truststore.password']
  credential_file = format('/etc/ranger/{repo_name}/cred.jceks')
  xa_audit_hdfs_is_enabled = default('/configurations/ranger-atlas-audit/xasecure.audit.destination.hdfs', False)

  # get ranger policy url
  policymgr_mgr_url = config['configurations']['ranger-atlas-security']['ranger.plugin.atlas.policy.rest.url']

  if not is_empty(policymgr_mgr_url) and policymgr_mgr_url.endswith('/'):
    policymgr_mgr_url = policymgr_mgr_url.rstrip('/')

  downloaded_custom_connector = None
  driver_curl_source = None
  driver_curl_target = None

  ranger_env = config['configurations']['ranger-env']

  # create ranger-env config having external ranger credential properties
  if not has_ranger_admin and enable_ranger_atlas:
    external_admin_username = default('/configurations/ranger-atlas-plugin-properties/external_admin_username', 'admin')
    external_admin_password = default('/configurations/ranger-atlas-plugin-properties/external_admin_password', 'admin')
    external_ranger_admin_username = default('/configurations/ranger-atlas-plugin-properties/external_ranger_admin_username', 'amb_ranger_admin')
    external_ranger_admin_password = default('/configurations/ranger-atlas-plugin-properties/external_ranger_admin_password', 'amb_ranger_admin')
    ranger_env = {}
    ranger_env['admin_username'] = external_admin_username
    ranger_env['admin_password'] = external_admin_password
    ranger_env['ranger_admin_username'] = external_ranger_admin_username
    ranger_env['ranger_admin_password'] = external_ranger_admin_password

  ranger_plugin_properties = config['configurations']['ranger-atlas-plugin-properties']
  ranger_atlas_audit = config['configurations']['ranger-atlas-audit']
  ranger_atlas_audit_attrs = config['configurationAttributes']['ranger-atlas-audit']
  ranger_atlas_security = config['configurations']['ranger-atlas-security']
  ranger_atlas_security_attrs = config['configurationAttributes']['ranger-atlas-security']
  ranger_atlas_policymgr_ssl = config['configurations']['ranger-atlas-policymgr-ssl']
  ranger_atlas_policymgr_ssl_attrs = config['configurationAttributes']['ranger-atlas-policymgr-ssl']

  policy_user = config['configurations']['ranger-atlas-plugin-properties']['policy_user']

  atlas_repository_configuration = {
    'username' : config['configurations']['ranger-atlas-plugin-properties']['REPOSITORY_CONFIG_USERNAME'],
    'password' : unicode(config['configurations']['ranger-atlas-plugin-properties']['REPOSITORY_CONFIG_PASSWORD']),
    'atlas.rest.address' : metadata_server_url,
    'commonNameForCertificate' : config['configurations']['ranger-atlas-plugin-properties']['common.name.for.certificate'],
    'ambari.service.check.user' : policy_user
  }

  custom_ranger_service_config = generate_ranger_service_config(ranger_plugin_properties)
  if len(custom_ranger_service_config) > 0:
    atlas_repository_configuration.update(custom_ranger_service_config)

  if security_enabled:
    atlas_repository_configuration['policy.download.auth.users'] = metadata_user
    atlas_repository_configuration['tag.download.auth.users'] = metadata_user

  atlas_ranger_plugin_repo = {
    'isEnabled': 'true',
    'configs': atlas_repository_configuration,
    'description': 'atlas repo',
    'name': repo_name,
    'type': 'atlas',
    }

# required when Ranger-KMS is SSL enabled
ranger_kms_hosts = default('/clusterHostInfo/ranger_kms_server_hosts',[])
has_ranger_kms = len(ranger_kms_hosts) > 0
is_ranger_kms_ssl_enabled = default('configurations/ranger-kms-site/ranger.service.https.attrib.ssl.enabled',False)
# ranger atlas plugin section end
# atlas admin login username password
atlas_admin_username = config['configurations']['atlas-env']['atlas.admin.username']
atlas_admin_password = config['configurations']['atlas-env']['atlas.admin.password']

mount_table_xml_inclusion_file_full_path = None
mount_table_content = None
if 'viewfs-mount-table' in config['configurations']:
  xml_inclusion_file_name = 'viewfs-mount-table.xml'
  mount_table = config['configurations']['viewfs-mount-table']

  if 'content' in mount_table and mount_table['content'].strip():
    mount_table_xml_inclusion_file_full_path = os.path.join(conf_dir, xml_inclusion_file_name)
    mount_table_content = mount_table['content']

# default kafka parameters
kafka_home = '/usr/lib/kafka'
kafka_bin = kafka_home+'/bin/kafka'
conf_dir = "/etc/kafka/conf"
limits_conf_dir = "/etc/security/limits.d"

# Used while upgrading the stack in a kerberized cluster and running kafka-acls.sh
zookeeper_connect = default("/configurations/kafka-broker/zookeeper.connect", None)

kafka_user_nofile_limit = default('/configurations/kafka-env/kafka_user_nofile_limit', 128000)
kafka_user_nproc_limit = default('/configurations/kafka-env/kafka_user_nproc_limit', 65536)

kafka_delete_topic_enable = default('/configurations/kafka-broker/delete.topic.enable', True)

# parameters for 2.2+
if stack_version_formatted and check_stack_feature(StackFeature.ROLLING_UPGRADE, stack_version_formatted):
  kafka_home = os.path.join(stack_root,  "current", "kafka-broker")
  kafka_bin = os.path.join(kafka_home, "bin", "kafka")
  conf_dir = os.path.join(kafka_home, "config")

kafka_user = config['configurations']['kafka-env']['kafka_user']
kafka_log_dir = config['configurations']['kafka-env']['kafka_log_dir']
kafka_pid_dir = status_params.kafka_pid_dir
kafka_pid_file = kafka_pid_dir+"/kafka.pid"
# This is hardcoded on the kafka bash process lifecycle on which we have no control over
kafka_managed_pid_dir = "/var/run/kafka"
kafka_managed_log_dir = "/var/log/kafka"
user_group = config['configurations']['cluster-env']['user_group']
java64_home = config['ambariLevelParams']['java_home']
kafka_env_sh_template = config['configurations']['kafka-env']['content']
kafka_jaas_conf_template = default("/configurations/kafka_jaas_conf/content", None)
kafka_client_jaas_conf_template = default("/configurations/kafka_client_jaas_conf/content", None)
kafka_hosts = config['clusterHostInfo']['kafka_broker_hosts']
kafka_hosts.sort()

zookeeper_hosts = config['clusterHostInfo']['zookeeper_server_hosts']
zookeeper_hosts.sort()
secure_acls = default("/configurations/kafka-broker/zookeeper.set.acl", False)
kafka_security_migrator = os.path.join(kafka_home, "bin", "zookeeper-security-migration.sh")

all_hosts = default("/clusterHostInfo/all_hosts", [])
all_racks = default("/clusterHostInfo/all_racks", [])

#Kafka log4j
kafka_log_maxfilesize = default('/configurations/kafka-log4j/kafka_log_maxfilesize',256)
kafka_log_maxbackupindex = default('/configurations/kafka-log4j/kafka_log_maxbackupindex',20)
controller_log_maxfilesize = default('/configurations/kafka-log4j/controller_log_maxfilesize',256)
controller_log_maxbackupindex = default('/configurations/kafka-log4j/controller_log_maxbackupindex',20)

if (('kafka-log4j' in config['configurations']) and ('content' in config['configurations']['kafka-log4j'])):
    log4j_props = config['configurations']['kafka-log4j']['content']
else:
    log4j_props = None

if 'ganglia_server_hosts' in config['clusterHostInfo'] and \
    len(config['clusterHostInfo']['ganglia_server_hosts'])>0:
  ganglia_installed = True
  ganglia_server = config['clusterHostInfo']['ganglia_server_hosts'][0]
  ganglia_report_interval = 60
else:
  ganglia_installed = False

metric_collector_port = ""
metric_collector_protocol = ""
metric_truststore_path= default("/configurations/ams-ssl-client/ssl.client.truststore.location", "")
metric_truststore_type= default("/configurations/ams-ssl-client/ssl.client.truststore.type", "")
metric_truststore_password= default("/configurations/ams-ssl-client/ssl.client.truststore.password", "")

set_instanceId = "false"
cluster_name = config["clusterName"]

if 'cluster-env' in config['configurations'] and \
        'metrics_collector_external_hosts' in config['configurations']['cluster-env']:
  ams_collector_hosts = config['configurations']['cluster-env']['metrics_collector_external_hosts']
  set_instanceId = "true"
else:
  ams_collector_hosts = ",".join(default("/clusterHostInfo/metrics_collector_hosts", []))

has_metric_collector = not len(ams_collector_hosts) == 0

if has_metric_collector:
  if 'cluster-env' in config['configurations'] and \
      'metrics_collector_external_port' in config['configurations']['cluster-env']:
    metric_collector_port = config['configurations']['cluster-env']['metrics_collector_external_port']
  else:
    metric_collector_web_address = default("/configurations/ams-site/timeline.metrics.service.webapp.address", "0.0.0.0:6188")
    if metric_collector_web_address.find(':') != -1:
      metric_collector_port = metric_collector_web_address.split(':')[1]
    else:
      metric_collector_port = '6188'
  if default("/configurations/ams-site/timeline.metrics.service.http.policy", "HTTP_ONLY") == "HTTPS_ONLY":
    metric_collector_protocol = 'https'
  else:
    metric_collector_protocol = 'http'

  host_in_memory_aggregation = str(default("/configurations/ams-site/timeline.metrics.host.inmemory.aggregation", True)).lower()
  host_in_memory_aggregation_port = default("/configurations/ams-site/timeline.metrics.host.inmemory.aggregation.port", 61888)
  is_aggregation_https_enabled = False
  if default("/configurations/ams-site/timeline.metrics.host.inmemory.aggregation.http.policy", "HTTP_ONLY") == "HTTPS_ONLY":
    host_in_memory_aggregation_protocol = 'https'
    is_aggregation_https_enabled = True
  else:
    host_in_memory_aggregation_protocol = 'http'
  pass

# Security-related params
kerberos_security_enabled = config['configurations']['cluster-env']['security_enabled']

kafka_kerberos_enabled = (('security.inter.broker.protocol' in config['configurations']['kafka-broker']) and
                          (config['configurations']['kafka-broker']['security.inter.broker.protocol'] in ("PLAINTEXTSASL", "SASL_PLAINTEXT", "SASL_SSL")))

kafka_other_sasl_enabled = not kerberos_security_enabled and check_stack_feature(StackFeature.KAFKA_LISTENERS, stack_version_formatted) and \
                           check_stack_feature(StackFeature.KAFKA_EXTENDED_SASL_SUPPORT, format_stack_version(version_for_stack_feature_checks)) and \
                           (("SASL_PLAINTEXT" in config['configurations']['kafka-broker']['listeners']) or
                            ("PLAINTEXTSASL" in config['configurations']['kafka-broker']['listeners']) or
                            ("SASL_SSL" in config['configurations']['kafka-broker']['listeners']))

if kerberos_security_enabled and stack_version_formatted != "" and 'kafka_principal_name' in config['configurations']['kafka-env'] \
  and check_stack_feature(StackFeature.KAFKA_KERBEROS, stack_version_formatted):
    _hostname_lowercase = config['agentLevelParams']['hostname'].lower()
    _kafka_principal_name = config['configurations']['kafka-env']['kafka_principal_name']
    kafka_jaas_principal = _kafka_principal_name.replace('_HOST',_hostname_lowercase)
    kafka_keytab_path = config['configurations']['kafka-env']['kafka_keytab']
    kafka_bare_jaas_principal = get_bare_principal(_kafka_principal_name)
    kafka_kerberos_params = "-Djava.security.auth.login.config="+ conf_dir +"/kafka_jaas.conf"
elif kafka_other_sasl_enabled:
  kafka_kerberos_params = "-Djava.security.auth.login.config="+ conf_dir +"/kafka_jaas.conf"
else:
    kafka_kerberos_params = ''
    kafka_jaas_principal = None
    kafka_keytab_path = None

# for curl command in ranger plugin to get db connector
jdk_location = config['ambariLevelParams']['jdk_location']

# ranger kafka plugin section start

# ranger host
ranger_admin_hosts = default("/clusterHostInfo/ranger_admin_hosts", [])
has_ranger_admin = not len(ranger_admin_hosts) == 0

# ranger support xml_configuration flag, instead of depending on ranger xml_configurations_supported/ranger-env, using stack feature
xml_configurations_supported = check_stack_feature(StackFeature.RANGER_XML_CONFIGURATION, version_for_stack_feature_checks)

ranger_admin_log_dir = default("/configurations/ranger-env/ranger_admin_log_dir","/var/log/ranger/admin")

# ranger kafka plugin enabled property
enable_ranger_kafka = default("configurations/ranger-kafka-plugin-properties/ranger-kafka-plugin-enabled", "No")
enable_ranger_kafka = True if enable_ranger_kafka.lower() == 'yes' else False

# ranger kafka-plugin supported flag, instead of dependending on is_supported_kafka_ranger/kafka-env.xml, using stack feature
is_supported_kafka_ranger = check_stack_feature(StackFeature.KAFKA_RANGER_PLUGIN_SUPPORT, version_for_stack_feature_checks)

# ranger kafka properties
if enable_ranger_kafka and is_supported_kafka_ranger:
  # get ranger policy url
  policymgr_mgr_url = config['configurations']['ranger-kafka-security']['ranger.plugin.kafka.policy.rest.url']

  if not is_empty(policymgr_mgr_url) and policymgr_mgr_url.endswith('/'):
    policymgr_mgr_url = policymgr_mgr_url.rstrip('/')

  # ranger audit db user
  xa_audit_db_user = default('/configurations/admin-properties/audit_db_user', 'rangerlogger')

  xa_audit_db_password = ''
  if not is_empty(config['configurations']['admin-properties']['audit_db_password']) and stack_supports_ranger_audit_db and has_ranger_admin:
    xa_audit_db_password = config['configurations']['admin-properties']['audit_db_password']

  # ranger kafka service/repository name
  repo_name = str(config['clusterName']) + '_kafka'
  repo_name_value = config['configurations']['ranger-kafka-security']['ranger.plugin.kafka.service.name']
  if not is_empty(repo_name_value) and repo_name_value != "{{repo_name}}":
    repo_name = repo_name_value

  ranger_env = config['configurations']['ranger-env']
  # create ranger-env config having external ranger credential properties
  if not has_ranger_admin and enable_ranger_kafka:
    external_admin_username = default('/configurations/ranger-kafka-plugin-properties/external_admin_username', 'admin')
    external_admin_password = default('/configurations/ranger-kafka-plugin-properties/external_admin_password', 'admin')
    external_ranger_admin_username = default('/configurations/ranger-kafka-plugin-properties/external_ranger_admin_username', 'amb_ranger_admin')
    external_ranger_admin_password = default('/configurations/ranger-kafka-plugin-properties/external_ranger_admin_password', 'amb_ranger_admin')
    ranger_env = {}
    ranger_env['admin_username'] = external_admin_username
    ranger_env['admin_password'] = external_admin_password
    ranger_env['ranger_admin_username'] = external_ranger_admin_username
    ranger_env['ranger_admin_password'] = external_ranger_admin_password

  ranger_plugin_properties = config['configurations']['ranger-kafka-plugin-properties']
  ranger_kafka_audit = config['configurations']['ranger-kafka-audit']
  ranger_kafka_audit_attrs = config['configurationAttributes']['ranger-kafka-audit']
  ranger_kafka_security = config['configurations']['ranger-kafka-security']
  ranger_kafka_security_attrs = config['configurationAttributes']['ranger-kafka-security']
  ranger_kafka_policymgr_ssl = config['configurations']['ranger-kafka-policymgr-ssl']
  ranger_kafka_policymgr_ssl_attrs = config['configurationAttributes']['ranger-kafka-policymgr-ssl']

  policy_user = config['configurations']['ranger-kafka-plugin-properties']['policy_user']

  ranger_plugin_config = {
    'username' : config['configurations']['ranger-kafka-plugin-properties']['REPOSITORY_CONFIG_USERNAME'],
    'password' : config['configurations']['ranger-kafka-plugin-properties']['REPOSITORY_CONFIG_PASSWORD'],
    'zookeeper.connect' : config['configurations']['ranger-kafka-plugin-properties']['zookeeper.connect'],
    'commonNameForCertificate' : config['configurations']['ranger-kafka-plugin-properties']['common.name.for.certificate']
  }

  atlas_server_hosts = default('/clusterHostInfo/atlas_server_hosts', [])
  has_atlas_server = not len(atlas_server_hosts) == 0
  hive_server_hosts = default('/clusterHostInfo/hive_server_hosts', [])
  has_hive_server = not len(hive_server_hosts) == 0
  hbase_master_hosts = default('/clusterHostInfo/hbase_master_hosts', [])
  has_hbase_master = not len(hbase_master_hosts) == 0
  ranger_tagsync_hosts = default('/clusterHostInfo/ranger_tagsync_hosts', [])
  has_ranger_tagsync = not len(ranger_tagsync_hosts) == 0
  storm_nimbus_hosts = default('/clusterHostInfo/nimbus_hosts', [])
  has_storm_nimbus = not len(storm_nimbus_hosts) == 0

  if has_atlas_server:
    atlas_notification_topics = default('/configurations/application-properties/atlas.notification.topics', 'ATLAS_HOOK,ATLAS_ENTITIES')
    atlas_notification_topics_list = atlas_notification_topics.split(',')
    hive_user = default('/configurations/hive-env/hive_user', 'hive')
    hbase_user = default('/configurations/hbase-env/hbase_user', 'hbase')
    atlas_user = default('/configurations/atlas-env/metadata_user', 'atlas')
    rangertagsync_user = default('/configurations/ranger-tagsync-site/ranger.tagsync.dest.ranger.username', 'rangertagsync')
    if len(atlas_notification_topics_list) == 2:
      atlas_hook = atlas_notification_topics_list[0]
      atlas_entity = atlas_notification_topics_list[1]
      ranger_plugin_config['setup.additional.default.policies'] = 'true'
      ranger_plugin_config['default-policy.1.name'] = atlas_hook
      ranger_plugin_config['default-policy.1.resource.topic'] = atlas_hook
      hook_policy_user = []
      if has_hive_server:
        hook_policy_user.append(hive_user)
      if has_hbase_master:
        hook_policy_user.append(hbase_user)
      if has_storm_nimbus and kerberos_security_enabled:
        storm_principal_name = config['configurations']['storm-env']['storm_principal_name']
        storm_bare_principal_name = get_bare_principal(storm_principal_name)
        hook_policy_user.append(storm_bare_principal_name)
      if len(hook_policy_user) > 0:
        ranger_plugin_config['default-policy.1.policyItem.1.users'] = ",".join(hook_policy_user)
        ranger_plugin_config['default-policy.1.policyItem.1.accessTypes'] = "publish"
      ranger_plugin_config['default-policy.1.policyItem.2.users'] = atlas_user
      ranger_plugin_config['default-policy.1.policyItem.2.accessTypes'] = "consume"
      ranger_plugin_config['default-policy.2.name'] = atlas_entity
      ranger_plugin_config['default-policy.2.resource.topic'] = atlas_entity
      ranger_plugin_config['default-policy.2.policyItem.1.users'] = atlas_user
      ranger_plugin_config['default-policy.2.policyItem.1.accessTypes'] = "publish"
      if has_ranger_tagsync:
        ranger_plugin_config['default-policy.2.policyItem.2.users'] = rangertagsync_user
        ranger_plugin_config['default-policy.2.policyItem.2.accessTypes'] = "consume"

  if kerberos_security_enabled:
    ranger_plugin_config['policy.download.auth.users'] = kafka_user
    ranger_plugin_config['tag.download.auth.users'] = kafka_user

  custom_ranger_service_config = generate_ranger_service_config(ranger_plugin_properties)
  if len(custom_ranger_service_config) > 0:
    ranger_plugin_config.update(custom_ranger_service_config)

  kafka_ranger_plugin_repo = {
    'isEnabled': 'true',
    'configs': ranger_plugin_config,
    'description': 'kafka repo',
    'name': repo_name,
    'repositoryType': 'kafka',
    'type': 'kafka',
    'assetType': '1'
  }

  downloaded_custom_connector = None
  previous_jdbc_jar_name = None
  driver_curl_source = None
  driver_curl_target = None
  previous_jdbc_jar = None

  if has_ranger_admin and stack_supports_ranger_audit_db:
    xa_audit_db_flavor = config['configurations']['admin-properties']['DB_FLAVOR']
    jdbc_jar_name, previous_jdbc_jar_name, audit_jdbc_url, jdbc_driver = get_audit_configs(config)

    downloaded_custom_connector = format("{tmp_dir}/{jdbc_jar_name}") if stack_supports_ranger_audit_db else None
    driver_curl_source = format("{jdk_location}/{jdbc_jar_name}") if stack_supports_ranger_audit_db else None
    driver_curl_target = format("{kafka_home}/libs/{jdbc_jar_name}") if stack_supports_ranger_audit_db else None
    previous_jdbc_jar = format("{kafka_home}/libs/{previous_jdbc_jar_name}") if stack_supports_ranger_audit_db else None
  xa_audit_db_is_enabled = False
  if xml_configurations_supported and stack_supports_ranger_audit_db:
    xa_audit_db_is_enabled = config['configurations']['ranger-kafka-audit']['xasecure.audit.destination.db']

  xa_audit_hdfs_is_enabled = default('/configurations/ranger-kafka-audit/xasecure.audit.destination.hdfs', False)
  ssl_keystore_password = config['configurations']['ranger-kafka-policymgr-ssl']['xasecure.policymgr.clientssl.keystore.password'] if xml_configurations_supported else None
  ssl_truststore_password = config['configurations']['ranger-kafka-policymgr-ssl']['xasecure.policymgr.clientssl.truststore.password'] if xml_configurations_supported else None
  credential_file = format('/etc/ranger/{repo_name}/cred.jceks')

  stack_version = get_stack_version('kafka-broker')
  setup_ranger_env_sh_source = format('{stack_root}/{stack_version}/ranger-kafka-plugin/install/conf.templates/enable/kafka-ranger-env.sh')
  setup_ranger_env_sh_target = format("{conf_dir}/kafka-ranger-env.sh")

  # for SQLA explicitly disable audit to DB for Ranger
  if has_ranger_admin and stack_supports_ranger_audit_db and xa_audit_db_flavor.lower() == 'sqla':
    xa_audit_db_is_enabled = False

# need this to capture cluster name from where ranger kafka plugin is enabled
cluster_name = config['clusterName']

# required when Ranger-KMS is SSL enabled
ranger_kms_hosts = default('/clusterHostInfo/ranger_kms_server_hosts',[])
has_ranger_kms = len(ranger_kms_hosts) > 0
is_ranger_kms_ssl_enabled = default('configurations/ranger-kms-site/ranger.service.https.attrib.ssl.enabled',False)

# ranger kafka plugin section end

namenode_hosts = default("/clusterHostInfo/namenode_hosts", [])
has_namenode = not len(namenode_hosts) == 0

hdfs_user = config['configurations']['hadoop-env']['hdfs_user'] if has_namenode else None
hdfs_user_keytab = config['configurations']['hadoop-env']['hdfs_user_keytab'] if has_namenode else None
hdfs_principal_name = config['configurations']['hadoop-env']['hdfs_principal_name'] if has_namenode else None
hdfs_site = config['configurations']['hdfs-site'] if has_namenode else None
default_fs = config['configurations']['core-site']['fs.defaultFS'] if has_namenode else None
hadoop_bin_dir = stack_select.get_hadoop_dir("bin") if has_namenode else None
hadoop_conf_dir = conf_select.get_hadoop_conf_dir() if has_namenode else None
kinit_path_local = get_kinit_path(default('/configurations/kerberos-env/executable_search_paths', None))
dfs_type = default("/clusterLevelParams/dfs_type", "")

mount_table_xml_inclusion_file_full_path = None
mount_table_content = None
if 'viewfs-mount-table' in config['configurations']:
  xml_inclusion_file_name = 'viewfs-mount-table.xml'
  mount_table = config['configurations']['viewfs-mount-table']

  if 'content' in mount_table and mount_table['content'].strip():
    mount_table_xml_inclusion_file_full_path = os.path.join(conf_dir, xml_inclusion_file_name)
    mount_table_content = mount_table['content']
import functools
#create partial functions with common arguments for every HdfsResource call
#to create/delete hdfs directory/file/copyfromlocal we need to call params.HdfsResource in code
HdfsResource = functools.partial(
  HdfsResource,
  user=hdfs_user,
  hdfs_resource_ignore_file = "/var/lib/ambari-agent/data/.hdfs_resource_ignore",
  security_enabled = kerberos_security_enabled,
  keytab = hdfs_user_keytab,
  kinit_path_local = kinit_path_local,
  hadoop_bin_dir = hadoop_bin_dir,
  hadoop_conf_dir = hadoop_conf_dir,
  principal_name = hdfs_principal_name,
  hdfs_site = hdfs_site,
  default_fs = default_fs,
  immutable_paths = get_not_managed_resources(),
  dfs_type = dfs_type,
)
