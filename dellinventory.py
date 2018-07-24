#!/usr/bin/env python3

import aiohttp
import argparse
import asyncio
import json
import jsonpath_ng as jsonpath
import logging
import sys

LOG = logging.getLogger(__name__)


async def chain(tasks):
    '''Execute a series of tasks in sequence.'''
    for task in tasks:
        await task


class Host:
    '''Represents a remote redfish v1 endpoint.'''

    redfish_path = '/redfish/v1'

    resolve_paths = (
        ('EthernetInterfaces',),
        ('Storage', 'Storage.Members[*].Drives'),
        ('Memory',),
        ('Processors',),
        ('Links.ManagedBy',),
        ('Bios',),
        ('Links.Oem.DELL.BootOrder',),
    )

    members = jsonpath.parse('Members')

    def __init__(self, addr, loop, session):
        self.addr = addr
        self.loop = loop
        self.session = session
        self.endpoint = 'https://{}'.format(addr)
        self.system = {}

    async def resolve_dict(self, obj, match):
        '''Resolve a single `odata.id` attribute.

        This expects a dictionary of the form:

            {"@odata.id": "/redfish/v1/..."}

        It replaces the associated key with the value of the content
        referred to by the `@odata.id` attribute.  If the returned
        content has a `Members` attribute, this will continue by
        replacing the original content by calling `resolve_list` on
        the value of the `Members` attribute.'''

        url = '{.endpoint}{}'.format(self, match.value['@odata.id'])
        data = await self.get(url)

        members = self.members.find(data)
        for submatch in members:
            await self.resolve_list(data, submatch)

        match.path.update(match.context.value, data)

    async def resolve_list(self, obj, match):
        '''Resolve a list of `@odata.id` attributes.

        This expects a list of the form:

            [
              {"@odata.id": ...},
              {"@odata.id": ...},
              ...
            ]

        It will replace each list item with the content from the URI
        referenced by the corresponding `@odata.id` attribute.'''

        tasks = []
        for item in match.value:
            url = '{.endpoint}{}'.format(self, item['@odata.id'])
            tasks.append(self.get(url))
        data = await asyncio.gather(*tasks)
        match.path.update(match.context.value, data)

    async def resolve(self, obj, path):
        '''Resolve `@odata.id` pointers'''

        LOG.info('%s: looking up information about %s', self.addr, path)
        expr = jsonpath.parse(path)
        target = expr.find(obj)
        LOG.debug('found %d matches', len(target))

        tasks = []
        for match in target:
            LOG.debug('resolved %s to result type %s', path, type(match.value))
            if isinstance(match.value, dict) and '@odata.id' in match.value:
                tasks.append(self.resolve_dict(obj, match))
            elif isinstance(match.value, list):
                tasks.append(self.resolve_list(obj, match))

        await asyncio.gather(*tasks)

    async def get(self, url):
        '''GET a URL and return the JSON content.'''

        LOG.debug('GET %s', url)
        async with self.session.get(url) as resp:
            assert resp.status == 200
            return await resp.json()

    async def get_system(self):
        '''Get summary information about the system.

        This is the main entrypoint for the Host class.  It assumes
        that there exists a remote resource
        /Systems/System.Embedded.1.'''

        LOG.info('%s: looking up information about system', self.addr)
        url = '{0.endpoint}{0.redfish_path}/Systems/System.Embedded.1'.format(self)  # NOQA
        try:
            system = await self.get(url)
            self.system = system

            tasks = []
            for pathset in self.resolve_paths:
                tasks.append(chain(
                    self.resolve(system, path) for path in pathset))
            await asyncio.gather(*tasks)
            self.system.update({'InventoryStatus': 'OKAY'})
        except aiohttp.client_exceptions.ClientError as err:
            self.system.update({'InventoryStatus': 'FAIL'})
            LOG.error('failed to connect to %s: %s (%s)',
                      self.addr, err, type(err))

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
