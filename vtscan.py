import argparse
import requests
import json
import time
import csv


def print_analysis_stats(stats):
    if stats is None:
        print("VirusTotal: No last analysis stats available.")
    else:
        print(f"VirusTotal: URL is marked malicious {stats['malicious']} times.")
        print(f"VirusTotal: URL is undetected by {stats['undetected']} scanners.")
        print(f"VirusTotal: URL is marked harmless by {stats['harmless']} scanners.")
        print(f"VirusTotal: URL is marked suspicious by {stats['suspicious']} scanners.")
        print(f"VirusTotal: URL timed out on {stats['timeout']} scanners.")


def check_virustotal_url(url, api_key, output_file=None):
    headers = {'x-apikey': api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
    data = json.loads(response.text)

    if response.status_code == 200:
        attributes = data['data']['attributes']
        stats = attributes['stats']
        print_analysis_stats(stats)
        if output_file:
            write_to_csv(output_file, url, stats)
    elif response.status_code == 404:
        headers = {'x-apikey': api_key, 'Content-Type': 'application/x-www-form-urlencoded'}
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=f"url={url}")
        data = json.loads(response.text)

        if response.status_code == 200:
            data_id = data['data']['id']
            print(f"VirusTotal: URL submitted for analysis. ID: {data_id}")

            # Store the ID of the URL scan
            url_scan_id = data_id

            # Wait for the scan to complete
            print("Waiting for the scan to complete...")
            while True:
                time.sleep(30)
                response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_scan_id}", headers=headers)
                data = json.loads(response.text)
                if response.status_code == 200:
                    attributes = data['data']['attributes']
                    stats = attributes['stats']
                    if attributes['status'] == 'completed':
                        print("Scan completed.")
                        print_analysis_stats(stats)
                        if output_file:
                            write_to_csv(output_file, url, stats)
                        break
                    else:
                        print("Scan in progress. Checking again in 30 seconds.")
                else:
                    print(f"VirusTotal: Error occurred. Status code: {response.status_code}. Message: {data['error']['message']}")
                    break
        else:
            print(f"VirusTotal: Error occurred. Status code: {response.status_code}. Message: {data['error']['message']}")
    else:
        print(f"VirusTotal: Error occurred. Status code: {response.status_code}. Message: {data['error']['message']}")


def write_to_csv(output_file, ip_address, stats):
    with open(output_file, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([ip_address, stats['malicious'], stats['undetected'], stats['harmless'], stats['suspicious'], stats['timeout']])


def main():
    parser = argparse.ArgumentParser(description='Check the reputation of URLs or IP addresses using VirusTotal API.')
    parser.add_argument('api_key', type=str, help='Your VirusTotal API key')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', type=str, help='The URL to check')
    group.add_argument('-l', '--list', type=str, help='Path to the text file containing a list of IP addresses')
    parser.add_argument('-o', '--output', type=str, help='Path to the output CSV file')

    args = parser.parse_args()

    api_key = args.api_key
    output_file = args.output

    if args.url:
        url = args.url
        check_virustotal_url(url, api_key, output_file)
    elif args.list:
        ip_file = args.list
        with open(ip_file, 'r') as file:
            ip_list = file.read().splitlines()
        for ip in ip_list:
            check_virustotal_url(ip, api_key, output_file)


if __name__ == '__main__':
    main()
