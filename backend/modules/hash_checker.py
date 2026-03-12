import hashlib

def calculate_hashes(file_content):
    return {
        'MD5': hashlib.md5(file_content).hexdigest(),
        'SHA1': hashlib.sha1(file_content).hexdigest(),
        'SHA256': hashlib.sha256(file_content).hexdigest()
    }