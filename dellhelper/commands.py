import aiohttp
import asyncio
import click
import json
import logging
import sys

import dellhelper.host


class State:

    def __init__(self):
        self.auth = None
        self.limit = None
        self.target = None


pass_state = click.make_pass_decorator(State, ensure=True)


@click.group()
@click.option('-u', '--user')
@click.option('-l', '--limit', type=int)
@click.option('-d', '--debug', 'loglevel', flag_value='DEBUG')
@click.option('-v', '--verbose', 'loglevel', flag_value='INFO', default=True)
@click.option('-q', '--quiet', 'loglevel', flag_value='WARNING')
@pass_state
def main(state, user, limit, loglevel):
    logging.basicConfig(level=loglevel)

    if user:
        creds = user.split(':', 1)
        state.auth = aiohttp.BasicAuth(*creds)

    state.limit = limit


async def task_sysinfo(hosts, loop, state):
    async with aiohttp.ClientSession(
        auth=state.auth,
        trust_env=True,
        connector=aiohttp.TCPConnector(verify_ssl=False,
                                       limit_per_host=state.limit),
    ) as session:
        tasks = []
        for addr in hosts:
            host = dellhelper.host.Host(addr, loop, session)
            task = loop.create_task(host.get_system())
            tasks.append(task)

        return await asyncio.gather(*tasks)


@main.command()
@click.option('-f', '--hosts-file', type=click.File('r'))
@click.option('-o', '--output', type=click.File('w'))
@click.argument('extra_hosts', nargs=-1)
@pass_state
def sysinfo(state, hosts_file, output, extra_hosts):
    hosts = []
    if hosts_file:
        hosts.extend(line for line in hosts_file.read().splitlines() if line)

    if extra_hosts:
        hosts.extend(extra_hosts)

    loop = asyncio.get_event_loop()
    task = loop.create_task(task_sysinfo(hosts, loop, state))
    inventory = loop.run_until_complete(task)

    with (output if output else sys.stdout) as fd:
        json.dump({x.addr: x.system for x in inventory}, fd, indent=2)


async def task_ping(hosts, loop, state):
    async with aiohttp.ClientSession(
        auth=state.auth,
        trust_env=True,
        connector=aiohttp.TCPConnector(verify_ssl=False,
                                       limit_per_host=state.limit),
    ) as session:
        tasks = []
        for addr in hosts:
            host = dellhelper.host.Host(addr, loop, session)
            task = loop.create_task(host.ping())
            tasks.append(task)

        return await asyncio.gather(*tasks)


@main.command()
@click.option('-f', '--hosts-file', type=click.File('r'))
@click.option('-o', '--output', type=click.File('w'))
@click.argument('extra_hosts', nargs=-1)
@pass_state
def ping(state, hosts_file, output, extra_hosts):
    hosts = []
    if hosts_file:
        hosts.extend(line for line in hosts_file.read().splitlines() if line)

    if extra_hosts:
        hosts.extend(extra_hosts)

    loop = asyncio.get_event_loop()
    task = loop.create_task(task_ping(hosts, loop, state))
    inventory = loop.run_until_complete(task)

    with (output if output else sys.stdout) as fd:
        json.dump({x.addr: x.ping_result for x in inventory}, fd, indent=2)


async def task_exportconfig(addr, target, loop, state):
    async with aiohttp.ClientSession(
        auth=state.auth,
        trust_env=True,
        connector=aiohttp.TCPConnector(verify_ssl=False,
                                       limit_per_host=state.limit),
    ) as session:
        host = dellhelper.host.Host(addr, loop, session)
        return await host.exportconfig(target)


@main.command()
@click.option('-o', '--output', type=click.File('w'))
@click.option('-t', '--target',
              type=click.Choice(['ALL', 'IDRAC', 'BIOS', 'NIC', 'RAID']))
@click.argument('host', nargs=1)
@pass_state
def exportconfig(state, output, target, host):
    loop = asyncio.get_event_loop()
    task = loop.create_task(task_exportconfig(host, target, loop, state))
    config = loop.run_until_complete(task)

    with (output if output else sys.stdout) as fd:
        json.dump(config, fd, indent=2)


async def task_importconfig(addrs, config, loop, state):
    async with aiohttp.ClientSession(
        auth=state.auth,
        trust_env=True,
        connector=aiohttp.TCPConnector(verify_ssl=False,
                                       limit_per_host=state.limit),
    ) as session:
        tasks = []
        for addr in addrs:
            host = dellhelper.host.Host(addr, loop, session)
            tasks.append(host.importconfig(config))

        await asyncio.gather(*tasks)


@main.command()
@click.option('-f', '--hosts-file', type=click.File('r'))
@click.option('-i', '--config', type=click.File('r'))
@click.option('--power-on', 'power', flag_value='on', default=True)
@click.option('--power-off', 'power', flag_value='off')
@click.option('-t', '--shutdown-timeout', type=int)
@click.option('-s', '--shutdown',
              type=click.Choice(['normal', 'force', 'none']),
              default='normal')
@click.argument('extra_hosts', nargs=-1)
@pass_state
def importconfig(state, hosts_file, config, power, shutdown_timeout,
                 shutdown, extra_hosts):
    config = json.load(config)

    hosts = []

    if hosts_file:
        hosts.extend(line for line in hosts_file.read().splitlines() if line)

    if extra_hosts:
        hosts.extend(extra_hosts)

    loop = asyncio.get_event_loop()
    task = loop.create_task(task_importconfig(hosts, config, loop, state))
    loop.run_until_complete(task)
