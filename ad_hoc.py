import csv
from netutils.config.compliance import compliance
import json
from napalm import get_network_driver
from rich import print as rprint
import concurrent.futures

features = [
    {
        "name": "username",
        "ordered": True,
        "section": [
            "username"
        ]
    },
    {
        "name": "enable",
        "ordered": True,
        "section": [
            "enable"
        ]
    }
]

environment = 'DEV'
inventory_file = f'inventory/host_{environment.lower()}.json'
csv_report_file = 'compliance_report.csv'


def process_device(host, ip_address):
    backup = f"device_configurations/{environment.lower()}/{host}.txt"
    intended = f"properties/compliance_netutils/intended.txt"
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
    summary_row = {'Device': 'Non-compliant'}
    for feature_name in feature_names:
        summary_row[feature_name] = 0

    for host, result in results:
        device_row = {'Device': host}
        for feature_name in feature_names:
            compliant = result.get(feature_name, {}).get('compliant', False)
            device_row[feature_name] = compliant
            if not compliant:
                summary_row[feature_name] += 1
        report_data[host] = device_row

    # Add summary row to report data
    report_data['Non-compliant'] = summary_row

    # Create the CSV report
    with open(csv_report_file, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=['Device'] + feature_names)
        writer.writeheader()
        writer.writerows(report_data.values())

    print(f"CSV report generated successfully: {csv_report_file}")
