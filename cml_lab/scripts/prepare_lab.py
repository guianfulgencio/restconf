"""
Prepare and start CML Lab
"""
import os
import sys
import time
import argparse
import socket
from cml_rest_methods import CML, logger

# Parser section
parser = argparse.ArgumentParser(description="Prepare and start CML lab for Dev infrastructure")
parser.add_argument('-u', '--username', type=str, metavar='',\
    help='CML username', required=True)
parser.add_argument('-p', '--password', type=str, metavar='',\
    help='CML password', required=True)
args = parser.parse_args()

def is_up(ip_add):
    '''
    Validate CML Lab IP address are up and reachable to port 22
    '''
    try:
        connection = socket.socket()
        connection.connect((ip_add, 22))
        connection.close()
        return True
    except Exception:
        return False

def main():
    '''
    Main script
    '''
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    cml = CML(args.username, args.password)
    cml.get_token()
    topology_file = "../dev_topology/phhq_cml.yaml"
    lab_node_ips = ["146.36.4.80", "146.36.4.81"]

    # Import lab
    lab_id = cml.import_lab(topology_file, 'PHHQ_Dev_Infra')

    # Start lab
    cml.start_lab(lab_id)

    # Wait nodes to come up
    timeout = 500
    logger.info('✅ WAITING FOR NODES TO COME UP')
    while timeout > 0 and lab_node_ips:
        for node_ip in lab_node_ips:
            if is_up(node_ip):
                lab_node_ips.remove(node_ip)
                logger.info('✅ %s IS UP', node_ip)
        time.sleep(1)
        timeout -= 1

    # Notify nodes that are still down
    for node_ip in lab_node_ips:
        logger.error('❌ node %s is not up', node_ip)
    if lab_node_ips:
        sys.exit(1)
    # Final info
    logger.info('✅ ALL NODES ARE UP')

if __name__ == "__main__":
    main()
