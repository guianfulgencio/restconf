"""
Custom module to apply IOS-XE configuration via RESTconf
"""
import json
import logging
import yaml
import requests
from requests.exceptions import HTTPError
from requests.exceptions import ConnectionError as conn_err
import urllib3
from napalm import get_network_driver
from rich.logging import RichHandler


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create logging
LOG_FORMAT = "%(asctime)s %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, handlers=[RichHandler(),\
                    logging.FileHandler("script.log")])
logger = logging.getLogger()


class Restconf():
    '''
    Restconf object for IOS-XE device configuration management
    '''
    def __init__(self, username, password, ip_address, hostname):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.compliance = 'properties/compliance'
        self.headers = {
            "Content-Type": "application/yang-data+json",
            "Accept": "application/yang-data+json"
        }
        self.auth = (self.username, self.password)

        # Base RESTconf URL endpoint for IOS-XE configuration
        self.rest_endpoint = f"https://{ip_address}/restconf/data/Cisco-IOS-XE-native:native"

        # Napalm driver
        driver = get_network_driver('ios')
        self.ssh_device = driver(
            hostname=ip_address,
            username=username,
            password=password,
            timeout=10
        )

    def service(self):
        '''
        check service compliance script
        configure to the device if not-compliant
        '''
        # open service compliance config script
        config_file = f"{self.compliance}/service.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)

        # IOS-XE Restconf URL endpoint for service configuration
        service_url = f"{self.rest_endpoint}/service"

        # Check device service compliance configuration
        try:
            # Check device current service configuration
            resp = requests.get(service_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            content = resp.text.replace("Cisco-IOS-XE-native:","")
            result = f"✅ {self.hostname} - service - OK"

            # If device configuration doesnt comply with service compliance configuration,
            # Push service compliance configuration into the device
            if config_script != json.loads(content):
                conf = requests.put(service_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(config_script), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - service - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - service - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - service - CONNECTION ERROR", self.hostname)

    def banner(self):
        '''
        Check device banner configuration
        NOTE: 
        RESTCONF apply configuration on IOS XE version 16.9.5 is buggy
        Working in version 16.11.1
        '''
        # Open banner compliance property
        config_file = f"{self.compliance}/banner.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            login_banner = config_script['banner']['login']['banner']
            login_banner_rest = login_banner.replace("\n","\\012").replace(" ","\\040")
            config_script['banner']['login']['banner'] = login_banner_rest

        # IOS-XE Restconf URL endpoint for banner configuration
        banner_url = f"{self.rest_endpoint}/banner"

        # Check banner configuration via SSH CLI command
        try:
            self.ssh_device.open()
            cli_command = ['show banner login']
            cli_output = self.ssh_device.cli(cli_command)
            device_login_banner = cli_output['show banner login']
            result = f"✅ {self.hostname} - banner - OK"
            
            # If device configuration doesnt comply with banner compliance configuration,
            # Push banner compliance configuration into the device via RESTconf
            if device_login_banner != login_banner[:-1]:
                banner_conf = requests.put(banner_url, headers=self.headers,\
                    auth=self.auth, data=json.dumps(config_script), verify=False)
                banner_conf.raise_for_status()
                result = f"✅ {self.hostname} - banner - CHANGED"

            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - banner - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - banner - CONNECTION ERROR", self.hostname)
        except Exception as err:
            logger.error("❌ %s - banner - UNKNOWN ERROR - %s", self.hostname, err)

    def call_home(self):
        '''
        Check call-home compliance script
        Configure device is non-compliant
        '''
        # open call-home compliance config script
        config_file = f"{self.compliance}/call-home.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)

        # IOS-XE Restconf URL endpoint for call-home configuration
        call_home_url = f"{self.rest_endpoint}/call-home"

        # Check device call-home compliance configuration
        try:
            # Check device current call-home configuration
            resp = requests.get(call_home_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            content = resp.text.replace("Cisco-IOS-XE-native:","").replace("Cisco-IOS-XE-call-home:","")
            result = f"✅ {self.hostname} - call-home - OK"

            # Build restconf payload
            email_addr = config_script['call-home']['contact-email-addr']
            profile = config_script['call-home']['profile']
            conf_payload = {
                "Cisco-IOS-XE-native:call-home": {
                    "Cisco-IOS-XE-call-home:contact-email-addr": email_addr,
                    "Cisco-IOS-XE-call-home:profile": profile
                }
            }

            # If device configuration doesnt comply with call-home compliance configuration,
            # Push call-home compliance configuration into the device
            if config_script != json.loads(content):
                conf = requests.put(call_home_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(conf_payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - call-home - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - call-home - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - call-home - CONNECTION ERROR", self.hostname)

    def enable(self):
        '''
        Check enable compliance script
        Configure device is non-compliant
        '''
        # open enable compliance config script
        config_file = f"{self.compliance}/enable.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)

        # IOS-XE Restconf URL endpoint for enable configuration
        enable_url = f"{self.rest_endpoint}/enable"

        # Check device enable compliance configuration
        try:
            # Check device current enable configuration
            resp = requests.get(enable_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            content = resp.text.replace("Cisco-IOS-XE-native:","")
            result = f"✅ {self.hostname} - enable - OK"

            # If device configuration doesnt comply with enable compliance configuration,
            # Push enable compliance configuration into the device
            if config_script != json.loads(content):
                conf = requests.put(enable_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(config_script), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - enable - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - enable - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - enable - CONNECTION ERROR", self.hostname)

    def user(self):
        '''
        Check username compliance script
        Configure device is non-compliant
        '''
        # open username compliance config script
        config_file = f"{self.compliance}/username.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)

        # IOS-XE Restconf URL endpoint for username configuration
        username_url = f"{self.rest_endpoint}/username"

        # Check device username compliance configuration
        try:
            # Check device current username configuration
            resp = requests.get(username_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            content = resp.text.replace("Cisco-IOS-XE-native:","")
            result = f"✅ {self.hostname} - username - OK"

            # If device configuration doesnt comply with username compliance configuration,
            # Push username compliance configuration into the device
            if config_script != json.loads(content):
                conf = requests.put(username_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(config_script), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - username - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - username - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - username - CONNECTION ERROR", self.hostname)

    def line(self, environment):
        '''
        Check line compliance script
        Configure device is non-compliant
        '''
        # open line compliance config script
        config_file = f"{self.compliance}/line.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            if environment.upper() == 'DEV':
                config_script['line'].pop('aux')
            
        # IOS-XE Restconf URL endpoint for line configuration
        line_url = f"{self.rest_endpoint}/line"

        try:
            # Check device current line configuration
            resp = requests.get(line_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            content = resp.text.replace("Cisco-IOS-XE-native:","")
            result = f"✅ {self.hostname} - line - OK"

            # If device configuration doesnt comply with line compliance configuration,
            # Push line compliance configuration into the device
            if config_script != json.loads(content):
                conf = requests.put(line_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(config_script), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - line - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - line - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - line - CONNECTION ERROR", self.hostname)

    def logging(self, region, interface, number):
        '''
        Check logging compliance script
        Configure device is non-compliant
        '''
        # open logging compliance config script
        config_file = f"{self.compliance}/logging.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            
        # IOS-XE Restconf URL endpoint for logging configuration
        logging_url = f"{self.rest_endpoint}/logging"

        # New logging payload
        host_list = config_script['logging']['host']['ipv4-host-list'].pop(region.upper())
        host_list = sorted(host_list,key=lambda i:i['ipv4-host'])
        int_name = f"{interface}{number}"
        payload = {
                "logging": {
                    "buffered": {
                        "size": {
                            "size-value": 128000
                        }
                    },
                    "host": {
                        "ipv4-host-list": host_list
                    },
                    "source-interface": [
                        {
                            "interface-name": int_name
                        }
                    ]
                }
            }
        try:
            # Check device current logging configuration
            resp = requests.get(logging_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.text.replace("Cisco-IOS-XE-native:","")
                content_dict = json.loads(content)
                try:
                    content_host_list = sorted(content_dict['logging']['host']['ipv4-host-list'], key=lambda i:i['ipv4-host'])
                except KeyError:
                    content_host_list = []
                result = f"✅ {self.hostname} - logging - OK"

                # If device configuration doesnt comply with logging compliance configuration,
                # Push logging compliance configuration into the device
                if (payload != content_dict) and (content_host_list != host_list):
                    conf = requests.put(logging_url, headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - logging - CHANGED"
            else:
                conf = requests.put(logging_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - logging - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - logging - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - logging - CONNECTION ERROR", self.hostname)


    def ntp(self, region, interface, number):
        '''
        Check ntp compliance script
        Configure device is non-compliant
        '''
        # open ntp compliance config script
        config_file = f"{self.compliance}/ntp.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            
        # IOS-XE Restconf URL endpoint for ntp configuration
        ntp_url = f"{self.rest_endpoint}/ntp"

        # New logging payload
        server_list = config_script['ntp']['server'].pop(region.upper())
        server_list = sorted(server_list['server-list'],key=lambda i:i['ip-address'])
        payload = {
            "Cisco-IOS-XE-native:ntp": {
                "Cisco-IOS-XE-ntp:access-group": config_script['ntp']['access-group'],
                "Cisco-IOS-XE-ntp:server": {
                    "server-list": server_list
                },
                "Cisco-IOS-XE-ntp:source": {
                    interface: number
                }
            }
        }

        try:
            # Check device current ntp configuration
            resp = requests.get(ntp_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            # Check device current ntp configuration
            resp = requests.get(ntp_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                try:
                    content_server_list = sorted(content['Cisco-IOS-XE-native:ntp']['Cisco-IOS-XE-ntp:server']['server-list'], key=lambda i:i['ip-address'])
                except KeyError:
                    content_server_list = []
                result = f"✅ {self.hostname} - ntp - OK"

                # If device configuration doesnt comply with ntp compliance configuration,
                # Push ntp compliance configuration into the device
                if (payload != content) and (content_server_list != server_list):
                    conf = requests.put(ntp_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - ntp - CHANGED"
            else:
                conf = requests.put(ntp_url , headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - ntp - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - ntp - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - ntp - CONNECTION ERROR", self.hostname)

    def spanning_tree(self):
        '''
        Check spanning-tree compliance script
        Configure device is non-compliant
        '''
        # open spanning-tree compliance config script
        config_file = f"{self.compliance}/spanning-tree.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            
        # IOS-XE Restconf URL endpoint for spanning-tree configuration
        spanning_tree_url = f"{self.rest_endpoint}/spanning-tree"

        # Spanning-tree payload
        payload = {
            "Cisco-IOS-XE-native:spanning-tree": {
                "Cisco-IOS-XE-spanning-tree:extend": config_script['spanning-tree']['extend'],
                "Cisco-IOS-XE-spanning-tree:mode": config_script['spanning-tree']['mode']
            }
        }

        try:
            # Check device current spanning-tree configuration
            resp = requests.get(spanning_tree_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            # Check device current spanning-tree configuration
            resp = requests.get(spanning_tree_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                result = f"✅ {self.hostname} - spanning-tree - OK"

                # If device configuration doesnt comply with spanning-tree compliance configuration,
                # Push spanning-tree compliance configuration into the device
                if payload != content:
                    conf = requests.put(spanning_tree_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - spanning-tree - CHANGED"
            else:
                conf = requests.put(spanning_tree_url , headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - spanning-tree - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - spanning-tree - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - spanning-tree - CONNECTION ERROR", self.hostname)

    def snmp(self):
        '''
        Check snmp compliance script
        Configure device is non-compliant
        '''
        # open snmp compliance config script
        config_file = f"{self.compliance}/snmp.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            
        # IOS-XE Restconf URL endpoint for snmp configuration
        snmp_url = f"{self.rest_endpoint}/snmp"

        # SNMP payload
        payload = {
            "Cisco-IOS-XE-native:snmp": {
                "Cisco-IOS-XE-snmp:ifmib": {
                    "ifindex": config_script['snmp']['ifmib']['ifindex']
                }
            }
        }
        try:
            # Check device current snmp configuration
            resp = requests.get(snmp_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            # Check device current snmp configuration
            resp = requests.get(snmp_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                result = f"✅ {self.hostname} - snmp - OK"

                # If device configuration doesnt comply with snmp compliance configuration,
                # Push snmp compliance configuration into the device
                if payload != content:
                    conf = requests.put(snmp_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - snmp - CHANGED"
            else:
                conf = requests.put(snmp_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - snmp - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - snmp - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - snmp - CONNECTION ERROR", self.hostname)

    def policy(self):
        '''
        Check policy compliance script
        Configure device is non-compliant
        '''
        # open policy compliance config script
        config_file = f"{self.compliance}/policy.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            
        # IOS-XE Restconf URL endpoint for policy configuration
        policy_url = f"{self.rest_endpoint}/policy"
        # policy payload
        payload = {
            "Cisco-IOS-XE-native:policy": {
                "Cisco-IOS-XE-policy:class-map": config_script['policy']['class-map'],
                "Cisco-IOS-XE-policy:policy-map": config_script['policy']['policy-map']
            }
        }
        try:
            # Check device current policy configuration
            resp = requests.get(policy_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            # Check device current policy configuration
            resp = requests.get(policy_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                result = f"✅ {self.hostname} - policy - OK"

                # If device configuration doesnt comply with policy compliance configuration,
                # Push policy compliance configuration into the device
                if payload != content:
                    conf = requests.put(policy_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - policy - CHANGED"
            else:
                conf = requests.put(policy_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - policy - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - policy - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - policy - CONNECTION ERROR", self.hostname)

    def vtp(self, site_code, environment):
        '''
        Check vtp compliance script
        Configure device is non-compliant
        '''
        # DEV environment doesnt have VTP feature
        if environment.upper() == 'DEV':
            return logger.info("❌ DEV environment doesnt have vtp feature")

        # open vtp compliance config script
        config_file = f"{self.compliance}/vtp.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            
        # IOS-XE Restconf URL endpoint for vtp configuration
        vtp_url = f"{self.rest_endpoint}/vtp"
        # vtp payload
        payload = {
            "Cisco-IOS-XE-native:vtp": {
                "Cisco-IOS-XE-vtp:domain": site_code,
                "Cisco-IOS-XE-vtp:mode": config_script['vtp']['mode']
            }
        }
        try:
            # Check device current vtp configuration
            resp = requests.get(vtp_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                result = f"✅ {self.hostname} - vtp - OK"

                # If device configuration doesnt comply with vtp compliance configuration,
                # Push vtp compliance configuration into the device
                if payload != content:
                    conf = requests.put(vtp_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - vtp - CHANGED"
            else:
                conf = requests.put(vtp_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - vtp - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - vtp - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - vtp - CONNECTION ERROR", self.hostname)

    def domain(self, site_code, interface, number):
        '''
        Check domain compliance script
        Configure device is non-compliant
        '''
            
        # IOS-XE Restconf URL endpoint for domain configuration
        domain_url = f"{self.rest_endpoint}/ip/domain"

        # domain payload
        payload = {
            "Cisco-IOS-XE-native:domain": {
                "lookup-settings": {
                    "lookup": {
                        "source-interface": {
                            interface: number
                        }
                    }
                },
                "name": f"{site_code.lower()}.chevrontexaco.net"
            }
        }
        
        try:
            # Check device current domain configuration
            resp = requests.get(domain_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                result = f"✅ {self.hostname} - domain - OK"

                # If device configuration doesnt comply with domain compliance configuration,
                # Push domain compliance configuration into the device
                if payload != content:
                    conf = requests.put(domain_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - domain - CHANGED"
            else:
                conf = requests.put(domain_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - domain - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - domain - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - domain - CONNECTION ERROR", self.hostname)

    def name_server(self, region):
        '''
        Check name-server compliance script
        Configure device is non-compliant
        '''
        # open name-server compliance config script
        config_file = f"{self.compliance}/ip.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            domain_server_script = config_script['ip']['name-server'].pop(region.upper())
            name_server_list = sorted(domain_server_script['no-vrf'])
            
        # IOS-XE Restconf URL endpoint for name-server configuration
        name_server_url = f"{self.rest_endpoint}/ip/name-server"

        # name-server payload
        payload = {
            "Cisco-IOS-XE-native:name-server": domain_server_script 
        }
        try:
            # Check device current name-server configuration
            resp = requests.get(name_server_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                content_server_list = sorted(content['Cisco-IOS-XE-native:name-server']['no-vrf'])
                result = f"✅ {self.hostname} - domain name-server - OK"

                # If device configuration doesnt comply with name-server compliance configuration,
                # Push name-server compliance configuration into the device
                if (payload != content) and (name_server_list != content_server_list):
                    conf = requests.put(name_server_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - domain name-server - CHANGED"
            else:
                conf = requests.put(name_server_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - domain name-server - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - domain name-server - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - domain name-server - CONNECTION ERROR", self.hostname)

    def forward_protocol(self):
        '''
        Check forward-protocol compliance script
        Configure device is non-compliant
        '''
        # open forward-protocol compliance config script
        config_file = f"{self.compliance}/ip.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            fwd_protocol_script = config_script['ip']['forward-protocol']
            
        # IOS-XE Restconf URL endpoint for forward-protocol configuration
        forward_protocol_url = f"{self.rest_endpoint}/ip/forward-protocol"

        # Forward protocol payload
        payload = {
            "Cisco-IOS-XE-native:forward-protocol": fwd_protocol_script
        }

        try:
            # Check device current name-server configuration
            resp = requests.get(forward_protocol_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                result = f"✅ {self.hostname} - forward-protocol - OK"

                # If device configuration doesnt comply with fwd-protocol compliance configuration,
                # Push fwd-protocol compliance configuration into the device
                if payload != content:
                    conf = requests.put(forward_protocol_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - forward-protocol - CHANGED"
            else:
                conf = requests.put(forward_protocol_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - forward-protocol - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - forward-protocol - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - forward-protocol - CONNECTION ERROR", self.hostname)

    def ftp(self, interface, number):
        '''
        Check ftp compliance script
        Configure device if non-compliant
        '''
            
        # IOS-XE Restconf URL endpoint for ftp configuration
        ftp_url = f"{self.rest_endpoint}/ip/ftp"

        # ftp payload
        payload = {
            "Cisco-IOS-XE-native:ftp": {
                "source-interface": {
                    interface: number
                }
            }
        }
        try:
            # Check device current ftp configuration
            resp = requests.get(ftp_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                result = f"✅ {self.hostname} - ftp - OK"

                # If device configuration doesnt comply with ftp compliance configuration,
                # Push ftp compliance configuration into the device
                if payload != content:
                    conf = requests.put(ftp_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - ftp - CHANGED"
            else:
                conf = requests.put(ftp_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - ftp - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - ftp - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - ftp - CONNECTION ERROR", self.hostname)

    def tftp(self, interface, number):
        '''
        Check tftp compliance script
        Configure device if non-compliant
        '''
            
        # IOS-XE Restconf URL endpoint for tftp configuration
        tftp_url = f"{self.rest_endpoint}/ip/tftp"

        # ftp payload
        payload = {
            "Cisco-IOS-XE-native:tftp": {
                "source-interface": {
                    interface: number
                }
            }
        }
        try:
            # Check device current tftp configuration
            resp = requests.get(tftp_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                result = f"✅ {self.hostname} - tftp - OK"

                # If device configuration doesnt comply with tftp compliance configuration,
                # Push tftp compliance configuration into the device
                if payload != content:
                    conf = requests.put(tftp_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - tftp - CHANGED"
            else:
                conf = requests.put(tftp_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - tftp - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - tftp - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - tftp - CONNECTION ERROR", self.hostname)

    def ip_config(self):
        '''
        Check ip config compliance script
        Configure device is non-compliant
        '''
        # open ip config compliance config script
        config_file = f"{self.compliance}/ip.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            ip_script = config_script['ip']
            
        for feature in ('source-route', 'ssh', 'tcp'):
            # IOS-XE Restconf URL endpoint for miscellaneous ip configuration
            feature_url = f"{self.rest_endpoint}/ip/{feature}"

            # Forward protocol payload
            payload = {
                f"Cisco-IOS-XE-native:{feature}": ip_script[feature]
            }

            try:
            # Check device current miscellaneous ip  configuration
                resp = requests.get(feature_url, headers=self.headers, auth=(self.auth), verify=False)
                resp.raise_for_status()
                if resp.status_code != 204:
                    content = resp.json()
                    result = f"✅ {self.hostname} - {feature} - OK"

                    # If device configuration doesnt comply with miscellaneous ip   compliance configuration,
                    # Push miscellaneous ip   compliance configuration into the device
                    if payload != content:
                        conf = requests.put(feature_url , headers=self.headers, auth=self.auth,\
                            data=json.dumps(payload), verify=False)
                        conf.raise_for_status()
                        result = f"✅ {self.hostname} - {feature} - CHANGED"
                else:
                    conf = requests.put(feature_url, headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - {feature} - CHANGED"
                logger.info(result)

            # HTTP and Connection Error section
            except HTTPError as httperr:
                logger.error("❌ %s - %s - HTTP ERROR - %s", self.hostname, feature, httperr)
            except conn_err:
                logger.error("❌ %s - %s - CONNECTION ERROR", self.hostname, feature)

    def access_list(self, region):
        '''
        Check access-list compliance script
        Configure device is non-compliant
        '''
        # open access-list compliance config script
        config_file = f"{self.compliance}/ip.yml"
        with open(config_file, 'r') as yaml_file:
            config_script = yaml.safe_load(yaml_file)
            access_list_script = config_script['ip']['access-list']
            standard_acl = access_list_script['standard']
            extended_acl = access_list_script['extended']
            new_std_acl = []
            for acl in standard_acl:
                if acl['name'] == 40:
                    acl['access-list-seq-rule'] = acl['access-list-seq-rule'].pop(region.upper())
                new_std_acl.append(acl)
            
        # IOS-XE Restconf URL endpoint for access-list configuration
        access_list_url = f"{self.rest_endpoint}/ip/access-list"

        # Forward protocol payload
        payload = {
            "Cisco-IOS-XE-native:access-list": {
                "Cisco-IOS-XE-acl:standard": new_std_acl,
                "Cisco-IOS-XE-acl:extended": extended_acl
            }
        }

        try:
            # Check device current access-list configuration
            resp = requests.get(access_list_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            if resp.status_code != 204:
                content = resp.json()
                result = f"✅ {self.hostname} - access-list - OK"

                # If device configuration doesnt comply with access-list compliance configuration,
                # Push access-list compliance configuration into the device
                # import ipdb; ipdb.set_trace()
                if payload != content:
                    conf = requests.put(access_list_url , headers=self.headers, auth=self.auth,\
                        data=json.dumps(payload), verify=False)
                    conf.raise_for_status()
                    result = f"✅ {self.hostname} - access-list - CHANGED"
            else:
                conf = requests.put(access_list_url, headers=self.headers, auth=self.auth,\
                    data=json.dumps(payload), verify=False)
                conf.raise_for_status()
                result = f"✅ {self.hostname} - access-list - CHANGED"
            logger.info(result)

        # HTTP and Connection Error section
        except HTTPError as httperr:
            logger.error("❌ %s - access-list - HTTP ERROR - %s", self.hostname, httperr)
        except conn_err:
            logger.error("❌ %s - access-list - CONNECTION ERROR", self.hostname)

if __name__ == "__main__":
    device = Restconf("svc-spectrum", "@<TIIca5<ut')qP(fT=6-", "146.36.4.81", "PHHQ7FSL01-DEV")
    # device.service()
    # device.banner()
    # device.enable()
    # device.user()
    # device.line('DEV')
    # device.logging('EMEA', 'GigabitEthernet', '1')
    # device.ntp('EMEA', 'GigabitEthernet', '1')
    # device.spanning_tree()
    # device.snmp()
    # device.call_home()
    # device.policy()
    # device.vtp('PHHQ', 'PROD')
    # device.domain('PHHQ', 'GigabitEthernet', '1')
    # device.policy()
    # device.name_server('US')
    # device.forward_protocol()
    # device.ftp('GigabitEthernet', '1')
    # device.tftp('GigabitEthernet', '1')
    # device.ip_config()
    device.access_list('APAC')

