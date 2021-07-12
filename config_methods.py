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

        # IOS-XE Restconf URL endpoint for service configuration
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

            # If device configuration doesnt comply with service compliance configuration,
            # Push service compliance configuration into the device
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

        # Check device call-home compliance configuration
        try:
            # Check device current call-home configuration
            resp = requests.get(enable_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            content = resp.text.replace("Cisco-IOS-XE-native:","")
            result = f"✅ {self.hostname} - enable - OK"

            # If device configuration doesnt comply with enable compliance configuration,
            # Push service compliance configuration into the device
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

        # IOS-XE Restconf URL endpoint for enable configuration
        username_url = f"{self.rest_endpoint}/username"

        # Check device call-home compliance configuration
        try:
            # Check device current call-home configuration
            resp = requests.get(username_url, headers=self.headers, auth=(self.auth), verify=False)
            resp.raise_for_status()
            content = resp.text.replace("Cisco-IOS-XE-native:","")
            result = f"✅ {self.hostname} - username - OK"

            # If device configuration doesnt comply with enable compliance configuration,
            # Push service compliance configuration into the device
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

if __name__ == "__main__":
    device = Restconf("svc-spectrum", "@<TIIca5<ut')qP(fT=6-", "146.36.4.80", "PHHQ7FSL01")
    # device.service()
    # device.banner()
    # device.enable()
    device.user()

