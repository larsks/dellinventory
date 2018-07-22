#!/usr/bin/env python3

from functools import reduce
import aiohttp
import argparse
import asyncio
import json
import logging
import operator
import sys

logging.basicConfig(level='DEBUG')
LOG = logging.getLogger(__name__)


class Host:
    system_map = (
        ('BiosVersion', 'bios_version'),
        ('HostName', 'hostname'),
        ('MemorySummary', 'memory_summary'),
        ('ProcessorSummary.Count', 'processor_summary'),
        ('SKU', 'service_tag'),
        ('SerialNumber', 'serial_number'),
        ('AssetTag', 'asset_tag'),
    )

    def __init__(self, addr, loop, session):
        self.addr = addr
        self.loop = loop
        self.session = session
        self.data = {
            'storage_devices': {},
            'storage_controllers': {},
            'network_devices': {},
        }

    async def resolve(self, entry, attr='Members'):
        tasks = []
        for member in entry.get(attr, []):
            url = 'https://{.addr}{member}'.format(
                self, member=member['@odata.id'])
            tasks.append(self.get(url))

        res = await asyncio.gather(*tasks)
        entry[attr] = {item['Id']: item for item in res}

    async def get(self, url):
        LOG.debug(url)
        async with self.session.get(url) as resp:
            assert resp.status == 200
            return await resp.json()

    async def get_system(self):
        tasks = (
            self.get_system_info(),
            self.get_nics(),
            self.get_disks(),
        )

        try:
            await asyncio.gather(*tasks)
        except aiohttp.client_exceptions.ClientError as err:
            LOG.error('failed to connect to %s: %s', self.addr, err)

        return self

    async def get_controller(self, controller):
        url = 'https://{.addr}{controller}'.format(self, controller=controller)  # NOQA
        res = await self.get(url)
        self.data['storage_controllers'][res['Id']] = res

    async def get_disks(self):
        url = 'https://{.addr}/redfish/v1/Systems/System.Embedded.1/SimpleStorage/Controllers'.format(self)  # NOQA
        res = await self.get(url)

        tasks = []
        for member in res['Members']:
            tasks.append(self.get_controller(member['@odata.id']))

        await asyncio.gather(*tasks)

    async def get_system_info(self):
        url = 'https://{.addr}/redfish/v1/Systems/System.Embedded.1'.format(self)  # NOQA
        res = await self.get(url)

        for path, name in self.system_map:
            self.data[name] = reduce(operator.getitem, path.split('.'), res)

    async def get_nics(self):
        url = 'https://{.addr}/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces'.format(self)  # NOQA
        res = await self.get(url)

        tasks = []
        for member in res['Members']:
            tasks.append(self.get_nic(member['@odata.id']))

        for nic in await asyncio.gather(*tasks):
            self.data['network_devices'][nic['Id']] = nic

    async def get_nic(self, nic):
        url = 'https://{.addr}{nic}'.format(self, nic=nic)  # NOQA
        return await self.get(url)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--hosts-file', '-f')
    p.add_argument('--user', '-u')
    p.add_argument('--output', '-o')
    p.add_argument('hosts', nargs='*', default=[])

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
        json.dump({x.addr: x.data for x in inventory}, fd, indent=2)


if __name__ == '__main__':
    main()
