import os
import hashlib

def get_sha2(attr):
    return hashlib.sha224(attr.encode('utf-8')).hexdigest()
    
def set_env(config):
    for k,v in config.items():
        os.environ[k] = v
