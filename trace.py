import socket
from argparse import ArgumentParser
import re
import json
import urllib.request


def trace(dist_ip):
    icmp_packet = b'\x08\x00\xf7\x4a\x00\x01\x00\xb4'
    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    ttl = 1
    cur_ip = None
    connection.settimeout(5)
    while ttl != 30 and cur_ip != dist_ip:
        connection.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        connection.sendto(icmp_packet, (dist_ip, 33434))
        try:
            packet, ip_port = connection.recvfrom(1024)
            cur_ip = ip_port[0]
            hop_info = '%d)   %s' % (ttl, cur_ip)
            if public_ip(cur_ip):
                hop_info += ' ' + str(simple_whois(cur_ip))
                yield hop_info

            else:
                yield hop_info + " its not public ip"
        except socket.timeout:
            yield '***  TimeOUT  ***'
        ttl += 1
    connection.close()


def public_ip(ip):
    local_ip_addresses_diapasons = (
        ('10.0.0.0', '10.255.255.255'),
        ('127.0.0.0', '127.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'))

    for diapason in local_ip_addresses_diapasons:
        if diapason[0] <= ip <= diapason[1]:
            return False
    return True


def init_parser():
    parser = ArgumentParser(prog="trace.py")
    parser.add_argument("-ip", action="store", help="ip to check.")
    return parser


def whois(addr, whois_server='whois.iana.org'):
    sock = socket.socket()
    sock.connect((whois_server, 43))
    if whois_server == 'whois.arin.net':
        sock.sendall(b'n '+addr.encode() + b'\r\n')
    else:
        sock.sendall(addr.encode() + b'\r\n')
    data = ''
    while True:
        buf = sock.recv(1024)
        data += buf.decode()
        if not buf:
            break
    sock.close()
    if whois_server == "whois.iana.org":
        whois_p = re.compile(r"whois:\s*(.*)")
        server = re.findall(whois_p, data)[0]
        return whois(addr, server)
    else:
        as_name_p = re.compile(r'origin:\s*(AS\d*)')
        as_name = re.findall(as_name_p, data)[0]
        country_p = re.compile(r'country:\s*(\w*)')
        country = re.findall(country_p, data)[0]
        return as_name, country


def simple_whois(addr):
    data = json.loads(
        urllib.request.urlopen('https://stat.ripe.net/data/prefix-overview/data.json?max_related=50&resource=%s' % addr)
        .read())
    if len(data['data']['asns']) == 0:
        return '', '', ''
    as_name = data['data']['asns'][0]['asn']
    provider = data['data']['asns'][0]['holder']
    data = json.loads(
        urllib.request.urlopen('https://stat.ripe.net/data/rir/data.json?resource=%s&lod=2' %
                               addr).read())
    country = data['data']['rirs'][0]['country']
    return as_name, country, provider


if __name__ == '__main__':
    parse = init_parser()
    args = parse.parse_args()
    if args.ip is not None:
        for message in trace(args.ip):
            print(message)
