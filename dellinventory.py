#!/usr/bin/env python3

import aiohttp
import argparse
import asyncio
import json
import jsonpointer
import logging
import sys

from functools import reduce
import operator

LOG = logging.getLogger(__name__)


class Host:
    system_resolve_members = (
        '/EthernetInterfaces',
        '/Storage',
        '/Storage/Drives',
        '/Memory',
        '/Processors',
    )

    system_resolve_ref = (
        '/Bios',
        '/Links/ManagedBy/0',
        '/Links/Oem/DELL/BootOrder',
    )

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

    def __init__(self, addr, loop, session):
        self.addr = addr
        self.loop = loop
        self.session = session
        self.system = {}

    async def resolve_members(self, obj, path):
        LOG.info('%s: looking up information about %s',
                 self.addr, path)

        id = jsonpointer.resolve_pointer(
            obj, '{}/@odata.id'.format(path))
        LOG.debug('%s: got id: %s', self.addr, id)

        url = 'https://{.addr}{}'.format(self, id)
        res = await self.get(url)

        tasks = []
        for member in res['Members']:
            url = 'https://{.addr}{member}'.format(
                self, member=member['@odata.id'])
            tasks.append(self.get(url))

        jsonpointer.set_pointer(
            obj, path, await asyncio.gather(*tasks))

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
            system = await self.get(url)
            self.system = system

            tasks = []
            for path in self.system_resolve_members:
                tasks.append(self.resolve_members(
                    system, path))
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
