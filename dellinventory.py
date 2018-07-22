#!/usr/bin/env python3

import aiohttp
import argparse
import asyncio
import json
import logging
import sys

from functools import reduce
import operator

LOG = logging.getLogger(__name__)


class Host:
    system_simple_attr = (
        ('BiosVersion', 'BiosVersion'),
        ('HostName', 'HostName'),
        ('Memory', 'Memory'),
        ('Processors', 'Processors'),
        ('MemorySummary', 'MemorySummary'),
        ('ProcessorSummary', 'ProcessorSummary'),
        ('SKU', 'ServiceTag'),
        ('SerialNumber', 'SerialNumber'),
        ('AssetTag', 'AssetTag'),
    )

    system_resolve_members = (
        ('EthernetInterfaces', 'EthernetInterfaces'),
        ('Storage', 'Storage'),
        ('Memory', 'Memory'),
        ('Processors', 'Processors'),
    )

    system_resolve_ref = (
        ('Bios', 'Bios'),
        ('Links.ManagedBy', 'ManagedBy'),
        ('Links.Oem.DELL.BootOrder', 'BootOrder'),
    )

    def __init__(self, addr, loop, session):
        self.addr = addr
        self.loop = loop
        self.session = session
        self.system = {}

    async def resolve_member_list(self, obj, attr, ref):
        LOG.info('%s: looking up information about %s',
                 self.addr, attr)

        url = 'https://{.addr}{ref}'.format(self, ref=ref)
        res = await self.get(url)

        tasks = []
        for member in res['Members']:
            url = 'https://{.addr}{member}'.format(
                self, member=member['@odata.id'])
            tasks.append(self.get(url))

        obj[attr] = await asyncio.gather(*tasks)

    async def resolve_ref(self, obj, attr, ref):
        LOG.info('%s: looking up information about %s',
                 self.addr, attr)

        url = 'https://{.addr}{ref}'.format(self, ref=ref)
        obj[attr] = await self.get(url)

    async def get(self, url):
        LOG.debug('GET %s', url)
        async with self.session.get(url) as resp:
            assert resp.status == 200
            return await resp.json()

    async def get_system(self):
        LOG.info('%s: looking up information about system', self.addr)
        url = 'https://{.addr}/redfish/v1/Systems/System.Embedded.1'.format(self)  # NOQA
        try:
            res = await self.get(url)
            system = {}
            self.system = system

            for path, name in self.system_simple_attr:
                try:
                    attr = reduce(operator.getitem, path.split('.'), res)
                except KeyError:
                    LOG.warn('attribute %s not available, skipping', path)
                    continue
                system[name] = attr

            tasks = []
            for path, name in self.system_resolve_members:
                try:
                    attr = reduce(operator.getitem, path.split('.'), res)
                except KeyError:
                    LOG.warn('attribute %s not available, skipping', path)
                    continue

                tasks.append(
                    self.resolve_member_list(
                        self.system, name, attr['@odata.id']))

            for path, name in self.system_resolve_ref:
                try:
                    LOG.debug('resolving path %s', path)
                    attr = reduce(operator.getitem, path.split('.'), res)
                    LOG.debug('path %s resolved to %s', path, attr)
                except KeyError:
                    LOG.warn('attribute %s not available, skipping', path)
                    import pdb; pdb.set_trace()
                    continue

                if isinstance(attr, list):
                    for i, item in enumerate(attr):
                        tasks.append(
                            self.resolve_ref(
                                self.system, '{}_{}'.format(name, i),
                                item['@odata.id']))
                else:
                    tasks.append(
                        self.resolve_ref(
                            self.system, name, attr['@odata.id']))

            await asyncio.gather(*tasks)

        except aiohttp.client_exceptions.ClientError as err:
            LOG.error('failed to connect to %s: %s (%s)', self.addr, err, type(err))

        return self


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--hosts-file', '-f')
    p.add_argument('--user', '-u')
    p.add_argument('--output', '-o')
    p.add_argument('hosts', nargs='*', default=[])

    g = p.add_argument_group()
    g.add_argument('--quiet', '-q',
                   action='store_const',
                   const='WARNING',
                   dest='loglevel')
    g.add_argument('--verbose', '-v',
                   action='store_const',
                   const='INFO',
                   dest='loglevel')
    g.add_argument('--debug', '-d',
                   action='store_const',
                   const='DEBUG',
                   dest='loglevel')

    p.set_defaults(loglevel='INFO')
    return p.parse_args()


async def get_all_hosts(hosts, loop, credentials=None):
    if credentials:
        _creds = credentials.split(':', 1)
        auth = aiohttp.BasicAuth(*_creds)
    else:
        auth = None

    async with aiohttp.ClientSession(
        auth=auth,
        trust_env=True,
        connector=aiohttp.TCPConnector(verify_ssl=False),
    ) as session:
        tasks = []
        for addr in hosts:
            host = Host(addr, loop, session)
            task = loop.create_task(host.get_system())
            tasks.append(task)

        return await asyncio.gather(*tasks)


def main():
    args = parse_args()
    logging.basicConfig(level=args.loglevel)

    hosts = []
    if args.hosts_file:
        with open(args.hosts_file) as fd:
            hosts.extend(line for line in fd.read().splitlines() if line)

    hosts.extend(args.hosts)

    loop = asyncio.get_event_loop()
    task = loop.create_task(get_all_hosts(hosts, loop,
                                          credentials=args.user))
    inventory = loop.run_until_complete(task)

    with (open(args.output, 'w') if args.output else sys.stdout) as fd:
        json.dump({x.addr: x.system for x in inventory}, fd, indent=2)


if __name__ == '__main__':
    main()
