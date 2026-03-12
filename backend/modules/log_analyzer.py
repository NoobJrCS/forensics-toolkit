import re

def parse_auth_log(log_content):
    failed_attempts = []
    ip_pattern = r'Failed password for .* from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'
    
    lines = log_content.decode('utf-8').split('\n')
    
    for line in lines:
        if 'Failed password' in line:
            match = re.search(ip_pattern, line)
            if match:
                failed_attempts.append({
                    'ip_address': match.group(1),
                    'raw_log': line.strip()
                })
                
    return failed_attempts