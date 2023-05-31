import csv
from netutils.config.compliance import compliance
import json
from rich import print as rprint
import concurrent.futures
from pprint import pprint

features = [
    {
        "name": "tacacs",
        "ordered": True,
        "section": [
            "tacacs server"
        ]
    },
]

environment = 'DEV'
inventory_file = f'inventory/host_{environment.lower()}.json'
csv_report_file = 'compliance_report.csv'


def process_device(host, ip_address):
    backup = f"device_configurations/{environment.lower()}/{host}.txt"
    intended = f"properties/compliance_netutils/intended_US.txt"
    network_os = "cisco_ios"
    compliance_report = compliance(features, backup, intended, network_os)
    return host, compliance_report


if __name__ == "__main__":
    with open(inventory_file, 'r') as inventory:
        devices = json.load(inventory)

    # Create a ThreadPoolExecutor with max_workers set to the number of devices
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(devices)) as executor:
        # Submit a task for each device to the executor
        futures = [executor.submit(process_device, host, ip_address) for host, ip_address in devices.items()]

        # Wait for all tasks to complete
        concurrent.futures.wait(futures)

        # Collect the results
        results = [future.result() for future in futures]

    # Prepare data for CSV report
    report_data = {}
    feature_names = [feature["name"] for feature in features]
    summary_row = {'Device': 'Total Non-compliant'}
    for feature_name in feature_names:
        summary_row[feature_name] = 0

    for host, result in results:
        device_row = {'Device': host}
        for feature_name in feature_names:
            compliant = result.get(feature_name, {}).get('compliant', False)
            compliant = 'Compliant' if compliant == True else 'Non-compliant'
            device_row[feature_name] = compliant
            if compliant == 'Non-compliant':
                summary_row[feature_name] += 1

        # Add missing and extra columns for the 'tacacs' feature
        tacacs_info = result.get('tacacs', {})
        tacacs_missing = ', '.join(t.strip() for t in tacacs_info.get('missing', []))
        tacacs_extra = ', '.join(t.strip() for t in tacacs_info.get('extra', []))
        device_row['tacacs_missing'] = tacacs_missing
        device_row['tacacs_extra'] = tacacs_extra

        report_data[host] = device_row

    # Add summary row to report data
    report_data['Total Non-compliant'] = summary_row

    # Create the CSV report
    with open(csv_report_file, 'w', newline='') as csv_file:
        fieldnames = ['Device'] + feature_names + ['tacacs_missing', 'tacacs_extra']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data.values())

    print(f"CSV report generated successfully: {csv_report_file}")
