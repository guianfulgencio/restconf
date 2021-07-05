"""
CML Delete Lab
"""
import argparse
from cml_rest_methods import CML, logger

# Parser section
parser = argparse.ArgumentParser(description="Delete CML Lab")
parser.add_argument('-u', '--username', type=str, metavar='',\
    help='CML username', required=True)
parser.add_argument('-p', '--password', type=str, metavar='',\
    help='CML password', required=True)
args = parser.parse_args()

def main():
    '''
    Main script
    ''' 
    cml = CML(args.username, args.password)
    cml.get_token()
    # Get Lab Id for the PHHQ_Dev_Infra
    lab_id = cml.get_lab_id('PHHQ_Dev_Infra')

    # Stop Lab
    cml.stop_lab(lab_id)

    # Wipe Lab
    cml.wipe_lab(lab_id)

    # Delete Lab
    cml.delete_lab(lab_id)

if __name__ == "__main__":
    main()

