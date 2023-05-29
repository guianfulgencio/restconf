"""
Get running configuration of the device
and upload it to phhq_device_configurations git repo

Required arguments
environment => 'DEV/PROD'
username => tacacs username
password => tacacs password
"""
import json
import argparse
from napalm import get_network_driver
from rich import print as rprint

parser = argparse.ArgumentParser(description="Get device running configuration")
parser.add_argument('-e', '--environment', type=str, metavar='',\
    help='Infrastructure environment [PROD/DEV]', required=True)
parser.add_argument('-u', '--username', type=str, metavar='',\
    help='Tacacs username', required=True)
parser.add_argument('-s', '--password', type=str, metavar='',\
    help='Tacacs password', required=True)
args = parser.parse_args()


def main():
    '''
    Main script to get device running configuration via CLI
    Python CLI module used is Napalm
    '''
    # Initialize variables
    environment = args.environment
    username = args.username
    password = args.password
    inventory_file = f'inventory/host_{environment.lower()}.json'

    # Gather device ip address details
    with open(inventory_file, 'r') as inventory:
        devices = json.load(inventory)

    # Loop through each device in devices inventory
    for host, ip_address in devices.items():
        rprint(f"\n[cyan]********** {host} **********[/cyan]")

        # Napalm driver
        driver = get_network_driver('ios')
        device = driver(
            hostname=ip_address,
            username=username,
            password=password,
            timeout=10
        )

        try:
            # Execute cli command 'show run'
            device.open()
            run_config = device.cli(['show run'])

            # Run configuration to be saved in git repo - phhq_device_configurations
            filename = f"device_configurations/{environment.lower()}/{host}.txt"
            with open(filename, 'w') as write_output:
                write_output.write(run_config['show run'])

            device.close()
            rprint(f"[green]✅ {host} - OK [/green]")
        except Exception as err:
            rprint(f"[red]❌ {host} - ERROR - {err}[/red]")

if __name__ == "__main__":
    main()