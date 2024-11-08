import subprocess
import re

# Predefined approved algorithms
APPROVED_KEX_ALGOS = [
    'curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512'
]
APPROVED_HOST_KEY_ALGOS = [
    'rsa-sha2-256','rsa-sha2-512', 'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'
]
APPROVED_CIPHER_STOC = [
    'aes256-gcm@openssh.com'
]
APPROVED_MAC_STOC = [
    'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512'
]

def check_approved_algorithms(ip_address):
    """
    Check if the server-side SSH algorithms match the approved algorithms.

    Args:
        ip_address (str): The IP address of the SSH server to connect to.

    Returns:
        bool: True if all device algorithms are approved, False otherwise.
    """
    # SSH command with -vv and BatchMode=yes to gather debug output without needing a login
    command = f"ssh -vv -o BatchMode=yes {ip_address}"

    # Run the SSH command and capture stderr output for verbose details
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = process.communicate()  # Capture stderr, which contains the debug output

    # Decode the stderr output, as debug information is sent to stderr
    ssh_output = stderr.decode('utf-8')

    # Locate the position of "peer server KEXINIT proposal" to start parsing from there
    start_index = ssh_output.find("debug2: peer server KEXINIT proposal")
    if start_index == -1:
        print("Error: 'peer server KEXINIT proposal' not found in the output.")
        return False  # If proposal not found, return False

    # Only consider the output starting from the peer server KEXINIT proposal
    relevant_output = ssh_output[start_index:]

    # Regular expressions specifically for the server-side algorithms
    kex_regex = re.compile(r'debug2: KEX algorithms:\s*([\w\-,@.]+)')
    host_key_regex = re.compile(r'debug2: host key algorithms:\s*([\w\-,@.]+)')
    cipher_stoc_regex = re.compile(r'debug2: ciphers stoc:\s*([\w\-,@.]+)')
    mac_stoc_regex = re.compile(r'debug2: MACs stoc:\s*([\w\-,@.]+)')

    # Parse the output using regex and split the results into lists
    kex_algorithms = kex_regex.search(relevant_output)
    kex_algorithms_list = kex_algorithms.group(1).split(',') if kex_algorithms else []

    host_key_algorithms = host_key_regex.search(relevant_output)
    host_key_algorithms_list = host_key_algorithms.group(1).split(',') if host_key_algorithms else []

    cipher_stoc = cipher_stoc_regex.search(relevant_output)
    cipher_stoc_list = cipher_stoc.group(1).split(',') if cipher_stoc else []

    mac_stoc = mac_stoc_regex.search(relevant_output)
    mac_stoc_list = mac_stoc.group(1).split(',') if mac_stoc else []

    # Perform subset check to ensure no unapproved algorithms are present
    if (set(kex_algorithms_list).issubset(APPROVED_KEX_ALGOS) and
        set(host_key_algorithms_list).issubset(APPROVED_HOST_KEY_ALGOS) and
        set(cipher_stoc_list).issubset(APPROVED_CIPHER_STOC) and
        set(mac_stoc_list).issubset(APPROVED_MAC_STOC)):
        return True
    else:
        return False
ip_address = "192.168.6.213"
if check_approved_algorithms(ip_address):
    print("The server's algorithms are all approved.")
else:
    print("The server has unapproved algorithms.")
