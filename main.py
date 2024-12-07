import csv

FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = 'sample.log'
OUTPUT_CSV = 'sample.csv'

def parse_log(file_path):

    with open(file_path, 'r') as file:
        return file.readlines()

def count_requests_per_ip(log_entries):

    ip_count = {}
    end_point_count = {}
    failed_logins = {}

    for entry in log_entries:

        ip = entry.split(" ")[0]
        ip_count[ip] = ip_count.get(ip, 0) + 1


        if '401' in entry or 'invalid credentials' in entry.lower():
            failed_logins[ip] = failed_logins.get(ip, 0) + 1


        parts = entry.split('"')
        if len(parts) > 1:
            request = parts[1].split(" ")[1]
            end_point_count[request] = end_point_count.get(request, 0) + 1


    most_accessed = max(end_point_count, key=end_point_count.get, default=None)


    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    return ip_count, most_accessed, end_point_count.get(most_accessed, 0), suspicious_ips

def save_to_csv(ip_count, most_accessed, most_accessed_count, suspicious_ips):
    with open(OUTPUT_CSV, 'w', newline='') as file:
        writer = csv.writer(file)


        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(ip_count.items())
        writer.writerow([])


        writer.writerow(['Most Accessed Endpoint', most_accessed])
        writer.writerow(['Access Count', most_accessed_count])
        writer.writerow([])


        writer.writerow(['Suspicious IPs (Failed Login Attempts > Threshold)', 'Failed Login Count'])
        writer.writerows(suspicious_ips.items())


def main():

    log_entries = parse_log(LOG_FILE)
    ip_count, most_accessed, most_accessed_count, suspicious_ips = count_requests_per_ip(log_entries)
    save_to_csv(ip_count, most_accessed, most_accessed_count, suspicious_ips)

if __name__ == '__main__':
    main()
