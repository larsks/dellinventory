#!/usr/bin/env python3

import aiohttp
import asyncio
import json
import jsonpath_ng as jsonpath
import logging

LOG = logging.getLogger(__name__)


async def chain(tasks):
    '''Execute a series of tasks in sequence.'''
    for task in tasks:
        await task


class HTTPError(Exception):
    def __init__(self, status_code):
        self.status_code = status_code

    def __str__(self):
        return '<HTTP Error {.status_code}>'.format(self)


class Host:
    '''Represents a remote redfish v1 endpoint.'''

    redfish_path = '/redfish/v1'
    export_configuration_target = '/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/EID_674_Manager.ExportSystemConfiguration'  # NOQA
    import_configuration_target = '/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Oem/EID_674_Manager.ImportSystemConfiguration'  # NOQA

    # A list of remote paths to resolve by replacing @odata.id attributes
    # with the content to which they refer. Each item in this list is a tuple;
    # all tuples will be resolved in parallel, and the elements of each
    # tuple will be resolved in sequence.
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
    default_export_target = 'ALL'

    def __init__(self, addr, loop, session):
        self.addr = addr
        self.loop = loop
        self.session = session
        self.endpoint = 'https://{}'.format(addr)
        self.system = {}
        self.log = logging.getLogger('{}.{}'.format(__name__, addr))

    async def importconfig(self, config, target=None):
        if target is None:
            target = self.default_export_target

        self.log.info('scheduling import configuration job for target',
                      target)

        url = '{0.endpoint}{0.import_configuration_target}'.format(self)
        headers = {'content-type': 'application/json'}
        reqparams = {
            'ShareParameters': {
                'Target': target,
            },
            'ImportBuffer': json.dumps(config)
        }
        async with self.session.post(url,
                                     headers=headers,
                                     json=reqparams) as response:
            if response.status != 202:
                raise HTTPError(response.status)

            jobid = response.headers['Location']

        return await self.exportconfig_wait(jobid)

    async def exportconfig(self, target=None):
        if target is None:
            target = self.default_export_target

        self.log.info('scheduling export configuration job for target %s',
                      target)
        url = '{0.endpoint}{0.export_configuration_target}'.format(self)
        headers = {'content-type': 'application/json'}
        reqparams = {
            'ExportFormat': 'JSON',
            'ShareParameters': {
                'Target': target,
            }
        }
        async with self.session.post(url,
                                     headers=headers,
                                     json=reqparams) as response:
            if response.status != 202:
                raise HTTPError(response.status)
            jobid = response.headers['Location']

        return await self.exportconfig_wait(jobid)

    async def exportconfig_wait(self, jobid):
        self.log.info('waiting for export configuration job %s',
                      jobid)
        url = '{.endpoint}{}'.format(self, jobid)

        while True:
            self.log.debug('checking status for %s', jobid)
            async with self.session.get(url) as response:
                if response.status not in [200, 202]:
                    raise HTTPError(response.status)

                if response.status == 200:
                    self.log.debug('found export response')
                    return await response.json()
                else:
                    await response.read()

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

        self.log.info('looking up information about %s', path)
        expr = jsonpath.parse(path)
        target = expr.find(obj)
        self.log.debug('found %d matches', len(target))

        if len(target) == 0:
            self.log.warning('found 0 matches for %s', path)

        tasks = []
        for match in target:
            self.log.debug('resolved %s to result type %s',
                           path, type(match.value))
            if isinstance(match.value, dict) and '@odata.id' in match.value:
                tasks.append(self.resolve_dict(obj, match))
            elif isinstance(match.value, list):
                tasks.append(self.resolve_list(obj, match))

        await asyncio.gather(*tasks)

    async def get(self, url):
        '''GET a URL and return the JSON content.'''

        self.log.debug('GET %s', url)
        async with self.session.get(url) as resp:
            if resp.status != 200:
                raise HTTPError(resp.status)

            return await resp.json()

    async def ping(self):
        url = '{0.endpoint}{0.redfish_path}'.format(self)

        try:
            await self.get(url)
            self.ping_result = (0, 'success')
        except HTTPError as err:
            self.log.error('failed with http status code %s', err.status_code)
            self.ping_result = (1, 'http status {}'.format(err.status_code))
        except aiohttp.client_exceptions.ClientError as err:
            self.log.error('failed with connection error (%s)', err)
            self.ping_result = (2, 'connection failed')

        return self

    async def get_system(self):
        '''Get summary information about the system.

        This is the main entrypoint for the Host class.  It assumes
        that there exists a remote resource
        /Systems/System.Embedded.1.'''

        self.log.info('looking up information about system')
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
        except HTTPError as err:
            self.system.update({'InventoryStatus': 'FAIL'})
            self.log.error('failed to connect: %s',
                           err)
        except aiohttp.client_exceptions.ClientError as err:
            self.system.update({'InventoryStatus': 'FAIL'})
            self.log.error('failed to connect: %s (%s)',
                           err, type(err))

        return self
