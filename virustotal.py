import requests
import csv
import argparse
import re

def query_virustotal(api_key, query_type, query_value):
    if query_type == 'domain':
        url = f"https://www.virustotal.com/api/v3/domains/{query_value}"
    elif query_type == 'hash':
        url = f"https://www.virustotal.com/api/v3/files/{query_value}"
    elif query_type == 'ip':
        query_value = re.sub(r"[^\d.]", "", query_value)  # Clean IP before using it
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{query_value}"
    
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None

def process_data(api_key, data_type, data_value):
    response = query_virustotal(api_key, data_type, data_value)
    if response and 'data' in response:
        attributes = response['data']['attributes']
        result = {'type': data_type, 'identifier': data_value}

        if data_type == 'domain':
            result.update({
                'registrar': attributes.get('registrar', 'N/A'),
                'creation_date': attributes.get('creation_date', 'N/A')
            })
        elif data_type == 'hash':
            result.update({
                'sha256': attributes.get('sha256', 'No Disponible'),
                'file_name': attributes.get('names', ['Desconocido'])[0]
            })
        elif data_type == 'ip':
            netname = re.search(r"netname: (\S+)", attributes.get('whois', ''))
            result.update({
                'asn': attributes.get('asn', 'N/A'),
                'network_name': netname.group(1) if netname else 'N/A'
            })

        # Calculate score
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        malicious = last_analysis_stats.get('malicious', 0)
        total = sum(last_analysis_stats.values())
        result['score'] = f"{malicious}/{total}" if total else "0/0"
        return result
    else:
        print(f"No data found for {data_type}: {data_value}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Query VirusTotal API and generate a CSV report for domains, hashes, or IP addresses.")
    parser.add_argument('-api', type=str, required=True, help='VirusTotal API key')
    parser.add_argument('-type', choices=['domain', 'hash', 'ip'], required=True, help='Type of data to query')
    parser.add_argument('-value', type=str, help='Single value to query')
    parser.add_argument('-p', type=str, help='Path to file containing values to query')
    args = parser.parse_args()

    output_file = f"{args.type}_report.csv"
    rows = []
    if args.value:
        data = process_data(args.api, args.type, args.value)
        if data:
            rows.append(data)
    elif args.p:
        with open(args.p, 'r') as file:
            for line in file:
                value = line.strip()
                if value:
                    data = process_data(args.api, args.type, value)
                    if data:
                        rows.append(data)
    
    if rows:
        fieldnames = list(rows[0].keys())
        with open(output_file, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        print(f"Report generated: {output_file}")

if __name__ == "__main__":
    main()
