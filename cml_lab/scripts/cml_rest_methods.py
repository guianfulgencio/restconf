""" Cisco CML REST methods
"""
import os
import sys
import json
import logging
import requests
import urllib3
from requests.exceptions import HTTPError
from dotenv import load_dotenv
from rich.logging import RichHandler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Create logging
LOG_FORMAT = "%(asctime)s %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, handlers=[RichHandler(),\
                    logging.FileHandler("script.log")])
logger = logging.getLogger()

class CML():
    '''
    REST methods to process Cisco CML
    '''
    def __init__(self, username, password):
        '''
        Initialize CML object
        '''
        load_dotenv()
        self.username = username
        self.password = password
        self.uri = os.getenv('CML_URI')
        self.lab_id = 0
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.payload = {
            "username": self.username,
            "password": self.password
        }

    def get_token(self):
        '''
        Get Authorization token from Cisco CML
        '''
        try:
            response = requests.post(f"{self.uri}/authenticate", headers=self.headers,\
                data=json.dumps(self.payload), verify=False)
            response.raise_for_status()
            token = response.json()
            self.headers['Authorization'] = f"Bearer {token}"
            logger.info("✅ Token successfully retrieved - %s", token)

        except HTTPError as httperr:
            logger.error("❌ Unable to get token - %s", httperr)
            sys.exit(1)

    def import_lab(self, labfile, labtitle):
        '''
        Import YAML file LAB into CML
        labfile => yaml file
        labtitle => string title for the imported lab
        '''
        with open(labfile, 'r') as topology_file:
            lab_topology = topology_file.read()
        try:
            response = requests.post(f"{self.uri}/import?title={labtitle}",\
                headers=self.headers, data=lab_topology, verify=False)
            response.raise_for_status()
            self.lab_id = response.json()['id']
            logger.info("✅ Lab successfully imported - %s", labtitle)
            return self.lab_id
        except HTTPError as httperr:
            logger.error("❌ Unable to import lab - %s", httperr)
            sys.exit(1)

    def start_lab(self, lab_id):
        '''
        Start CML LAB topology
        '''
        try:
            response = requests.put(f"{self.uri}/labs/{lab_id}/start",\
                headers=self.headers, verify=False)
            response.raise_for_status()
            logger.info("✅ Lab Started - %s", lab_id)
        except HTTPError as httperr:
            logger.error("❌ Unable to start lab - %s", httperr)
            sys.exit(1)

    def stop_lab(self, lab_id):
        '''
        Stop CML LAB topology
        '''
        try:
            response = requests.put(f"{self.uri}/labs/{lab_id}/stop",\
                headers=self.headers, verify=False)
            response.raise_for_status()
            logger.info("✅ Lab Stopped - %s", lab_id)
        except HTTPError as httperr:
            logger.error("❌ Unable to stop lab - %s", httperr)
            sys.exit(1)

    def wipe_lab(self, lab_id):
        '''
        Wipe CML LAB topology configuration
        '''
        try:
            response = requests.put(f"{self.uri}/labs/{lab_id}/wipe",\
                headers=self.headers, verify=False)
            response.raise_for_status()
            logger.info("✅ Lab configuration wiped - %s", lab_id)
        except HTTPError as httperr:
            logger.error("❌ Unable to wipe lab configuration - %s", httperr)
            sys.exit(1)

    def delete_lab(self, lab_id):
        '''
        Delete CML Lab topology
        '''
        try:
            response = requests.delete(f"{self.uri}/labs/{lab_id}",\
                headers=self.headers, verify=False)
            response.raise_for_status()
            logger.info("✅ Lab deleted - %s", lab_id)
        except HTTPError as httperr:
            logger.error("❌ Unable to delete lab - %s", httperr)
            sys.exit(1)


    def get_lab_id(self, title):
        '''
        Get CML Lab ID by passing the lab title
        title - string
        return LAB id
        '''
        try:
            response = requests.get(f"{self.uri}/labs",\
                headers=self.headers, verify=False)
            response.raise_for_status()
            for lab_id in response.json():
                lab_details = requests.get(f"{self.uri}/labs/{lab_id}",\
                    headers=self.headers, verify=False)
                lab_details.raise_for_status()
                if title in lab_details.json()['lab_title']:
                    logger.info("✅ Lab ID found for title %s - %s", title, lab_id)
                    return lab_id
            logger.error("❌ Lab ID not found for title - %s", title)
            sys.exit(1)
        except HTTPError as httperr:
            logger.error("❌ Unable to get Lab ID - %s", httperr)
            sys.exit(1)
