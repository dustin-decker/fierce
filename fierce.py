#!/usr/bin/env python3

import argparse
import functools
import http.client
import ipaddress
import os
import random
import socket
import time
from multiprocessing import Process, Queue
import json

import dns.name
import dns.query
import dns.resolver
import dns.reversename
import dns.zone


def find_subdomain_list_file(filename):
    # First check the list directory relative to where we are. This
    # will typically happen if they simply cloned the Github repository
    filename_path = os.path.join(os.path.dirname(__file__), "lists", filename)
    if os.path.exists(filename_path):
        return os.path.abspath(filename_path)

    try:
        import pkg_resources
    except ImportError:
        return filename

    # If the relative check failed then attempt to find the list file
    # in the pip package directory. This will typically happen on pip package
    # installs (duh)
    #
    # Here's how pip itself handles this:
    #
    #     https://github.com/pypa/pip/blob/master/pip/commands/show.py
    #
    try:
        fierce = pkg_resources.get_distribution('fierce')
    except pkg_resources.DistributionNotFound:
        return filename

    if isinstance(fierce, pkg_resources.Distribution):
        paths = []
        if fierce.has_metadata('RECORD'):
            lines = fierce.get_metadata_lines('RECORD')
            paths = [l.split(',')[0] for l in lines]
            paths = [os.path.join(fierce.location, p) for p in paths]
        elif fierce.has_metadata('installed-files.txt'):
            lines = fierce.get_metadata_lines('installed-files.txt')
            paths = [l for l in lines]
            paths = [os.path.join(fierce.egg_info, p) for p in paths]

        for p in paths:
            if filename == os.path.basename(p):
                return p

    # If we couldn't find anything just return the original list file
    return filename


def head_request(url):
    conn = http.client.HTTPConnection(url, timeout=3)

    try:
        conn.request("HEAD", "/")
    except socket.gaierror:
        return []
    except (ConnectionRefusedError, socket.error):
        return []
    else:
        try:
            resp = conn.getresponse()
        except socket.timeout:
            return []
    finally:
        conn.close()

    resp_headers = resp.getheaders()
    if resp_headers:
        headers = {}
        for header in resp_headers:
            headers[header[0]] = header[1]

        return headers
    else:
        return None

def concatenate_subdomains(domain, subdomains):
    result = dns.name.Name(tuple(subdomains) + domain.labels)

    if not result.is_absolute():
        result = result.concatenate(dns.name.root)

    return result


def query(resolver, domain, record_type='A'):
    try:
        resp = resolver.query(domain, record_type, raise_on_no_answer=False)
        if resp.response.answer:
            return resp

        # If we don't receive an answer from our current resolver let's
        # assume we received information on nameservers we can use and
        # perform the same query with those nameservers
        if resp.response.additional and resp.response.authority:
            ns = [
                rdata.address
                for additionals in resp.response.additional
                for rdata in additionals.items
                ]
            resolver.nameservers = ns
            return query(resolver, domain, record_type)

        return None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return None


def reverse_query(resolver, ip):
    return query(resolver, dns.reversename.from_address(ip), record_type='PTR')


def zone_transfer(address, domain):
    try:
        return dns.zone.from_xfr(dns.query.xfr(address, domain))
    except (ConnectionResetError, dns.exception.FormError):
        return None
    except (ConnectionRefusedError, dns.exception.FormError):
        return None


def get_class_c_network(ip):
    ip = int(ip)
    floored = ipaddress.ip_address(ip - (ip % (2 ** 8)))
    class_c = ipaddress.IPv4Network('{}/24'.format(floored))

    return class_c


def traverse_expander(ip, n=5):
    class_c = get_class_c_network(ip)

    result = [ipaddress.IPv4Address(ip + i) for i in range(-n, n + 1)]
    result = [i for i in result if i in class_c]

    return result


def wide_expander(ip):
    class_c = get_class_c_network(ip)

    result = list(class_c)

    return result


def search_filter(domains, address):
    return any(domain in address for domain in domains)


def find_nearby(resolver, ips, filter_func=None):
    reversed_ips = {str(i): reverse_query(resolver, str(i)) for i in ips}
    reversed_ips = {k: v for k, v in reversed_ips.items() if v is not None}

    if filter_func:
        reversed_ips = {k: v for k, v in reversed_ips.items() if v and filter_func(v[0].to_text())}

    if not reversed_ips:
        return None

    return {k: v[0].to_text() for k, v in reversed_ips.items() if v}


def fierce(**kwargs):
    """
    fierce function is directly callable and returns a results dictionary
    :param concurrency:
    :param domain:
    :param print:
    :param connect:
    :return: python dictionary of results
    """

    resolver = dns.resolver.Resolver()

    nameservers = []
    if kwargs.get('dns_servers'):
        nameservers = kwargs['dns_servers']
    elif kwargs.get('dns_file'):
        nameservers = [ns.strip() for ns in open(kwargs["dns_file"]).readlines()]

    if nameservers:
        resolver.nameservers = nameservers

    reversed_ips = False
    if kwargs.get("range"):
        internal_range = ipaddress.IPv4Network(kwargs.get("range"))
        reversed_ips = find_nearby(resolver, list(internal_range))

    if not kwargs.get("concurrency"):
        numWorkers = 1
    else:
        numWorkers = kwargs.get("concurrency")

    if kwargs.get("domain"):
        domain = dns.name.from_text(kwargs['domain'])
    else:
        return
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)

    # DNS times out sometimes
    for attempt in range(0, 5):
        ns = query(resolver, domain, record_type='NS')
        if ns is not None:
            domain_name_servers = [n.to_text() for n in ns]
            break
        time.sleep(3)


    soa = query(resolver, domain, record_type='SOA')
    soa_mname = soa[0].mname
    master = query(resolver, soa_mname, record_type='A')
    master_address = master[0].address

    zone = {}
    zone_dump = zone_transfer(master_address, domain)
    if zone_dump is not None:
        zone = {(k.to_text() + '.' + domain.to_text()): v.to_text(k) for k, v in zone_dump.items()}

    random_subdomain = str(random.randint(1e10, 1e11))
    random_domain = concatenate_subdomains(domain, [random_subdomain])
    wildcard = query(resolver, random_domain, record_type='A')

    if kwargs.get('subdomains'):
        subdomains = kwargs["subdomains"]
    else:
        if kwargs.get("subdomain_file"):
            subdomain_file = kwargs.get("subdomain_file")
        else:
            subdomain_file = find_subdomain_list_file('default.txt')

        subdomains = [sd.strip() for sd in open(subdomain_file).readlines()]


    visited = set()

    hosts = Queue()

    def subdomainWorker(visited):
        while True:
            subdomain = subdomainQueue.get()
            if type(subdomain) is int:
                return
            url = concatenate_subdomains(domain, [subdomain])
            try:
                record = query(resolver, url, record_type='A')
            except dns.exception.Timeout:
                return

            if record is None:
                continue

            try:
                ip = ipaddress.IPv4Address(record[0].address)
            except TypeError:
                return

            headers = False
            if kwargs.get('connect') and not ip.is_private:
                headers = head_request(str(ip))

            if kwargs.get("traverse"):
                traverse = kwargs.get("traverse")
            else:
                traverse = 5

            if kwargs.get("wide"):
                ips = wide_expander(ip)
            else:
                ips = traverse_expander(ip, traverse)

            filter_func = None
            if kwargs.get("search"):
                filter_func = functools.partial(search_filter, kwargs["search"])

            ips = set(ips) - set(visited)
            visited |= ips

            hosts.put({
                str(url): {
                    'ip': str(ip),
                    'headers': headers,
                    'nearby': find_nearby(resolver, ips, filter_func=filter_func)
                }
            })

            if kwargs.get("delay"):
                time.sleep(kwargs["delay"])
            else:
                time.sleep(0)

    workers = []
    subdomainQueue = Queue()
    for i in range(numWorkers):
        p = Process(target=subdomainWorker, args=(visited,))
        workers.append(p)
        p.start()
    for subdomain in subdomains:
        subdomainQueue.put(subdomain)
    while True:
        if subdomainQueue.empty():
            for i in range(numWorkers):
                # workers terminate when they encounter an int
                subdomainQueue.put(50)
            for worker in workers:
                # blocks until process terminates
                worker.join()

            def get_hosts(q):
                d = {}
                while q.qsize() > 0:
                    for fqdn, nearby in q.get().items():
                        d[fqdn] = nearby
                return d

            results = {'target': domain.to_text(),
                       'hosts': get_hosts(hosts),
                       'nameservers': domain_name_servers,
                       'soa_mname': soa_mname.to_text(),
                       'zone': zone if len(zone) > 0 else False,
                       'wildcard': bool(wildcard),
                       'range': reversed_ips
                       }

            if kwargs.get('pretty_print'):
                print(json.dumps(results, indent=4))
            if kwargs.get('print'):
                print(json.dumps(results))

            return results


def parse_args():
    p = argparse.ArgumentParser(description='''
        A DNS reconnaissance tool for locating non-contiguous IP space.
        ''', formatter_class=argparse.RawTextHelpFormatter)

    p.add_argument('--print', action='store_true',
                   help='print the results')
    p.add_argument('--pretty-print', action='store_true', default=True,
                   help='print the results')
    p.add_argument('--domain', action='store',
                   help='domain name to test')
    p.add_argument('--concurrency', action='store', type=int,
                   help='number of cuncurrent processes')
    p.add_argument('--connect', action='store_true',
                   help='attempt HTTP connection to non-RFC 1918 hosts')
    p.add_argument('--wide', action='store_true',
                   help='scan entire class c of discovered records')
    p.add_argument('--traverse', action='store', type=int, default=5,
                   help='scan IPs near discovered records, this won\'t enter adjacent class c\'s')
    p.add_argument('--search', action='store', nargs='+',
                   help='filter on these domains when expanding lookup')
    p.add_argument('--range', action='store',
                   help='scan an internal IP range, use cidr notation')
    p.add_argument('--delay', action='store', type=float, default=None,
                   help='time to wait between lookups')

    subdomain_group = p.add_mutually_exclusive_group()
    subdomain_group.add_argument('--subdomains', action='store', nargs='+',
                                 help='use these subdomains')
    subdomain_group.add_argument('--subdomain_file', action='store',
                                 default="default.txt",
                                 help='use subdomains specified in this file (one per line)')

    dns_group = p.add_mutually_exclusive_group()
    dns_group.add_argument('--dns-servers', action='store', nargs='+',
                           help='use these dns servers for reverse lookups')
    dns_group.add_argument('--dns-file', action='store',
                           help='use dns servers specified in this file for reverse lookups (one per line)')

    args = p.parse_args()

    # Attempt to intelligently find the subdomain list depending on
    # how this library was installed.
    if args.subdomain_file and not os.path.exists(args.subdomain_file):
        args.subdomain_file = find_subdomain_list_file(args.subdomain_file)

    return args


def main():
    args = parse_args()

    fierce(**vars(args))


if __name__ == "__main__":
    main()
