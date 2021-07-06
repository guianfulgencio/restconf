import socket
import requests
from requests.exceptions import HTTPError
import urllib3
import logging
from unicon import Connection
from unicon.core.errors import ConnectionError
from pyats import aetest

logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to check device connectivity status
def check_conn(ip_add, port):
    '''
    Check connection socket status
    ip_add => IPv4 address value xx.xx.xx.xx
    port => TCP port 
    '''
    try:
        connection = socket.socket()
        connection.connect((ip_add, port))
        connection.close()
        return True
    except Exception:
        return False

# Test cases:
# Check device connectivity protocol status
class Telnet_test(aetest.Testcase):
    uid = 'Telnet Test'

    @aetest.test
    def port_check(self, steps, devices):
        for device, ip in devices.items():
            with steps.start(f'{device}', continue_=True) as step:
                result = check_conn(ip, 23)
                if not result:
                    step.passed("✅ Telnet port is NOT open")
                step.failed("❌ Telnet port is open. This port is unsecure.")

class SSH_test(aetest.Testcase):
    uid = 'SSH Test'

    @aetest.test
    def connection(self, steps, devices, username, password):
        for device, ip in devices.items():
            with steps.start(f'{device}', continue_=True) as step:
                with step.start('Port check', continue_=True) as substep1:
                    result = check_conn(ip, 22)
                    if result:
                        substep1.passed("✅ SSH port is open.")
                    substep1.failed("❌ SSH port is NOT open.")

                with step.start('Tacacs Authentication', continue_=True) as substep2:
                    dev = Connection(
                        hostname=device,
                        start=[f'ssh {ip}'],
                        credentials={'default': {
                            'username': username,
                            'password': password}
                        },
                        os='iosxe',
                        log_stdout=False,
                        init_exec_commands=['term length 0'],
                        init_config_commands=[],
                        learn_hostname=True,
                        logfile=False
                    )
                    try:
                        dev.connect()
                        logger.info("Successfully connected to %s", device)
                        cmd = dev.execute('show version | i uptime')
                        logger.info(cmd)
                        dev.disconnect()
                        logger.info("Disconnected...")
                        substep2.passed('✅ Authentication successful')
                    except ConnectionError as conn_err:
                        substep2.failed(f'❌ Authentication failed - {conn_err}')

class HTTP_test(aetest.Testcase):
    uid = 'HTTP Test'

    @aetest.test
    def port_check(self, steps, devices):
        for device, ip in devices.items():
            with steps.start(f'{device}', continue_=True) as step:
                result = check_conn(ip, 80)
                if not result:
                    step.passed("✅ HTTP port is NOT open")
                step.failed("❌ HTTP port is open. This port is unsecure.")

class HTTPS_test(aetest.Testcase):
    uid = 'HTTPS Test'
        
    @aetest.test
    def connection(self, steps, devices, username, password):
        for device, ip in devices.items():
            with steps.start(f'{device}', continue_=True) as step:
                with step.start(f'Port check', continue_=True) as substep1:
                    result = check_conn(ip, 443)
                    if result:
                        substep1.passed("✅ HTTPS port is open.")
                    substep1.failed("❌ HTTPS port is NOT open.")

                with step.start('RESTconf check', continue_=True) as substep2:
                    headers = {
                        "Accept": "application/yang-data+json",
                        "Content-Type": "application/yang-data+json"
                    }
                    url = f"https://{ip}/restconf/data/native/hostname"
                    try:
                        logger.info(f"Sending REST message to {device}")
                        response = requests.get(url, headers=headers, auth=(username, password), verify=False)
                        response.raise_for_status()
                        logger.info(response.json())
                        substep2.passed("✅ RESTconf is enabled")
                    except HTTPError as http_err:
                        substep2.failed(http_err)
                    except Exception as err:
                        substep2.failed(err)

if __name__ == '__main__':
    import os
    import sys
    import json
    import argparse

    # Change working directory
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)

    # creating our own parser to parse script arguments
    parser = argparse.ArgumentParser(description = "Test script")
    parser.add_argument('--environment', dest = 'environment', type= str)
    parser.add_argument('--username', dest = 'username', type= str)
    parser.add_argument('--password', dest = 'password', type= str)
    args, sys.argv[1:] = parser.parse_known_args(sys.argv[1:])

    inventory_file = '../../inventory/phhq_dev.json'
    if args.environment.upper() == 'PROD':
        inventory_file = '../../inventory/phhq_prod.json'

    with open(inventory_file, 'r') as inv_file:
        inventory_dict = json.load(inv_file)

    # set logger level
    logger.setLevel(logging.INFO)

    aetest.main(devices=inventory_dict, username=args.username, password=args.password)
