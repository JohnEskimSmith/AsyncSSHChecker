#!/usr/bin/env python
__author__ = "SAI"

import argparse
import asyncio
import datetime


from collections import namedtuple
from time import time
from hashlib import md5, sha256
from ipaddress import IPv4Address, IPv4Network
from os import path
from sys import version_info

from typing import (NamedTuple,
                    Iterator,
                    BinaryIO,
                    TextIO,
                    )

import asyncssh
import uvloop

from aioconsole import ainput
from aiofiles import open as aiofiles_open
from ujson import dumps as ujson_dumps

CONST_STOP_STAGE = b"STOP"

CONST_C = 1024
CONST_DEFAULT_PORT = 22
CONST_TIMEOUT = 7

CONST_SERVER_HOST_KEY_ALGS = {"ssh-rsa": [md5, sha256],
                              "ecdsa-sha2-nistp256": [md5, sha256]}


def create_target_ssh_protocol(ip_str: str,
                               port: int) -> Iterator:
    Target = namedtuple("Target", ["ip", "port"])
    current_settings = {"ip": ip_str,
                        "port": port}
    target = Target(**current_settings)
    yield target


def create_targets_ssh_protocol(ip_str: str,
                                port: int) -> Iterator[NamedTuple]:
    """
    Функция для обработки "подсетей" и создания "целей"
    :param ip_str:
    :param settings:
    :return:
    """
    hosts = IPv4Network(ip_str, strict=False)
    for host in hosts:
        for target in create_target_ssh_protocol(str(host), port):
            yield target


def check_ip(ip_str: str) -> bool:
    """
    Проверка строки на ip адрес
    :param ip_str:
    :return:
    """
    try:
        IPv4Address(ip_str)
        return True
    except BaseException:
        return False


def check_network(net_str: str) -> bool:
    """
    Проверка строки на ip адрес сети
    :param net_str:
    :return:
    """
    try:
        IPv4Network(net_str)
        return True
    except BaseException:
        return False


async def write_to_stdout(object_file: BinaryIO,
                          record_str: str):
    """
    write in 'wb' mode to object_file, input string in utf-8
    :param object_file:
    :param record_str:
    :return:
    """
    await object_file.write(record_str.encode("utf-8") + b"\n")


async def write_to_file(object_file: TextIO,
                        record_str: str):
    """
    write in 'text' mode to object_file
    :param object_file:
    :param record_str:
    :return:
    """
    await object_file.write(record_str + '\n')


async def read_input_stdin(queue_input: asyncio.Queue,
                           settings: dict,
                           path_to_file: str="") -> int:
    count_input = 0
    while True:
        try:
            _tmp_input = await ainput()  # read str from stdin
            linein = _tmp_input.strip()
            if any([check_ip(linein), check_network(linein)]):
                for target in create_targets_ssh_protocol(linein, port=settings["port"]):
                    if target:
                        await queue_input.put(target)
                        count_input += 1
        except EOFError:
            await queue_input.put(CONST_STOP_STAGE)
            break
    return count_input


async def read_input_file(queue_input: asyncio.Queue,
                          settings: dict,
                          path_to_file: str) -> int:
    count_input = 0
    async with aiofiles_open(path_to_file, mode="rt") as f:  # read str
        async for line in f:
            linein = line.strip()
            if any([check_ip(linein), check_network(linein)]):
                for target in create_targets_ssh_protocol(linein, port=settings["port"]):
                    if target:
                        await queue_input.put(target)
                        count_input += 1
    await queue_input.put(CONST_STOP_STAGE)
    return count_input


async def work_with_queue_tasks(queue_results: asyncio.Queue,
                                queue_prints: asyncio.Queue) -> None:
    while True:
        task = await queue_results.get()
        if task == CONST_STOP_STAGE:
            await queue_prints.put(CONST_STOP_STAGE)
            break
        await task


async def _get_server_host_key(target, *, tunnel=(), family=(), flags=0,
                               local_addr=None, client_version=(),
                               kex_algs=(), config=(), options=None) -> tuple[dict, str]:

    def conn_factory():
        current_loop = asyncio.get_event_loop()
        return asyncssh.SSHClientConnection(current_loop, options, wait="kex")

    current_loop = asyncio.get_event_loop()
    host = target.ip
    port = target.port
    result = {}
    error = ""
    for server_host_key_algs in CONST_SERVER_HOST_KEY_ALGS.keys():
        options = asyncssh.SSHClientConnectionOptions(
            options, config=config, host=host, port=port, tunnel=tunnel,
            family=family, local_addr=local_addr, known_hosts=None,
            server_host_key_algs=server_host_key_algs, x509_trusted_certs=None,
            x509_trusted_cert_paths=None, x509_purposes="any", gss_host=None,
            kex_algs=kex_algs, client_version=client_version)

        try:
            try:
                conn = await asyncssh.connection._connect(options=options,
                                                          loop=current_loop,
                                                          flags=flags,
                                                          conn_factory=conn_factory,
                                                          msg="Fetching server host key from",
                                                          sock=None)
            except OSError as oserror:
                if oserror.errno == 113:
                    error = f"dial tcp {host}:{port}: connect: no route to host"
                    break
            else:
                server_host_key = conn.get_server_host_key()
                result[server_host_key_algs] = server_host_key
                if not result.get("version"):
                    try:
                        server_version = conn.get_extra_info("server_version")
                        result["version"] = server_version
                    except:
                        result["version"] = ""
                conn.abort()
                await conn.wait_closed()
        except:
            error = "unknow-error"
    if not result and not error:
        error = "unknow-error"
    return result, error


async def worker_single_fingerprint(target,
                                    semaphore: asyncio.Semaphore,
                                    queue_out: asyncio.Queue,
                                    timeout: int = CONST_TIMEOUT) -> None:

    value = {}
    error = ''
    status = False

    async with semaphore:
        try:
            result, error_message = await asyncio.wait_for(
                    _get_server_host_key(target=target, client_version="AsyncSSH-Fingerprint"),
                    timeout=timeout)
            if result:
                value["version"] = result.get("version")
                for name, algorithms in CONST_SERVER_HOST_KEY_ALGS.items():
                    if data := result.get(name):
                        value[name] = {}
                        for algorithm in algorithms:
                            function_hash_name = algorithm.__name__.replace("openssl_", "")
                            value[name][function_hash_name] = algorithm(data.public_data).hexdigest()
                    status = True
            else:
                error = error_message
        except asyncio.TimeoutError:
            error = "timeout-error"
        except:
            error = "unknown-error"
    if error or not status:
        value["error"] = "unknown-error" if not error else error
    await queue_out.put((value, target, status))


async def work_with_create_tasks_queue(queue_with_input: asyncio.Queue,
                                       queue_with_tasks: asyncio.Queue,
                                       queue_out: asyncio.Queue,
                                       semaphore: asyncio.Semaphore,
                                       timeout: int) -> None:

    while True:
        item = await queue_with_input.get()  # item is a Target
        if item == CONST_STOP_STAGE:
            await queue_with_tasks.put(CONST_STOP_STAGE)
            break
        elif item:
            await queue_with_tasks.put(
                asyncio.create_task(worker_single_fingerprint(item, semaphore, queue_out, timeout=timeout))
            )


async def work_with_queue_result(queue_out: asyncio.Queue,
                                 filename,
                                 mode_write) -> tuple[float, int, int]:
    number_of_successes = 0
    number_of_failed = 0
    start_time = time()
    if mode_write == 'a':
        method_write_result = write_to_file
    else:
        method_write_result = write_to_stdout
    _z = datetime.datetime.now(datetime.timezone(datetime.timedelta(0))).astimezone().tzinfo
    async with aiofiles_open(filename, mode=mode_write) as file_with_results:
        while True:
            value: tuple[dict, bool] | bytes = await queue_out.get()
            if value == CONST_STOP_STAGE:
                break
            line, target, status = value
            if status:
                number_of_successes += 1

                # region copy like from zgrab2 ssh module
                result_row = {"ip": target.ip,
                              "port": target.port,
                              "data":{"ssh": {}}}
                result_row["data"]["ssh"]["status"] = "success"
                result_row["data"]["ssh"]["protocol"] = "ssh"
                result_row["data"]["ssh"]["timestamp"] = datetime.datetime.now(tz=_z).strftime("%Y-%m-%dT%H:%M:%S%z")
                result_row["data"]["ssh"]["result"] = {}
                result_row["data"]["ssh"]["result"]["server_id"] = {}
                result_row["data"]["ssh"]["result"]["server_id"]["raw"] = line.get("version", "")
                result_row["data"]["ssh"]["result"]["key_exchange"] = {}
                result_row["data"]["ssh"]["result"]["key_exchange"] = {}
                result_row["data"]["ssh"]["result"]["key_exchange"]["server_host_key"] = {}
                if "version" in line:
                    line.pop("version")
                result_row["data"]["ssh"]["result"]["key_exchange"]["server_host_key"]["algorithms"] = line
                # endregion
            else:
                # region copy like from zgrab2 ssh module
                number_of_failed += 1
                result_row = {"ip": target.ip,
                              "port": target.port,
                              "data": {"ssh": {}}}
                result_row["data"]["ssh"]["status"] = "error"
                result_row["data"]["ssh"]["protocol"] = "ssh"
                result_row["data"]["ssh"]["result"] = {}
                result_row["data"]["ssh"]["timestamp"] = datetime.datetime.now(tz=_z).strftime("%Y-%m-%dT%H:%M:%S%z")
                result_row["data"]["ssh"]["error"] = line["error"]
                # endregion
            await method_write_result(file_with_results, ujson_dumps(result_row))

    duration_time_sec = round(time() - start_time, 4)
    return duration_time_sec, number_of_successes, number_of_failed


async def main(settings):
    queue_input = asyncio.Queue()
    queue_results = asyncio.Queue()
    queue_prints = asyncio.Queue()
    task_semaphore = asyncio.Semaphore(settings["senders"])

    method_create_targets = settings["method_create_targets"]
    path_to_file_targets = settings["path_to_file_targets"]
    output_file = settings["output_file"]
    mode_write = settings["mode_write"]

    read_input = method_create_targets(queue_input, settings, path_to_file_targets)  # create targets
    create_tasks = work_with_create_tasks_queue(queue_input, queue_results, queue_prints, task_semaphore, settings["timeout"])  # execution
    execute_tasks = work_with_queue_tasks(queue_results, queue_prints)
    print_output = work_with_queue_result(queue_prints, output_file, mode_write)

    async with asyncio.TaskGroup() as tg:
        task_read_in = tg.create_task(read_input)
        task_output = tg.create_task(print_output)
        for worker in [create_tasks, execute_tasks]:
            tg.create_task(worker)

    if settings["statistics"]:
        # {"statuses":{"ssh":{"successes":4,"failures":1}},"start":"2023-10-09T00:42:17+03:00","end":"2023-10-09T00:42:20+03:00","duration":"3.067355464s"}
        count_input = task_read_in.result()
        duration_time_sec, count_good, count_error = task_output.result()
        statistics_output = {"statuses": {"ssh": {"successes": count_good,
                                                  "failures": count_error,
                                                  "valid": count_input}},
                             "duration": duration_time_sec}
        async with aiofiles_open("/dev/stdout", mode="wb") as stats:
            await stats.write(ujson_dumps(statistics_output).encode("utf-8") + b"\n")


def create_settings(args) -> dict | None:
    if not args.port:
        print('need set port, exit.')
        exit(1)
    settings = {}
    settings["senders"] = args.senders
    settings["port"] = args.port

    if not args.input_file:
        # set method - async read from stdin (str)
        settings["method_create_targets"] = read_input_stdin
    else:
        # set method - async read from file(txt, str)
        if not path.isfile(args.input_file):
            print(f'ERROR: file not found: {args.input_file}')
            exit(1)
        else:
            settings["path_to_file_targets"] = args.input_file
            settings["method_create_targets"] = read_input_file

    if not args.output_file:
        output_file, mode_write = '/dev/stdout', 'wb'
    else:
        output_file, mode_write = args.output_file, 'a'

    settings["output_file"] = output_file
    settings["mode_write"] = mode_write

    settings["statistics"] = args.statistics
    settings["timeout"] = args.timeout
    return settings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Async SSH fingerprint lite(asyncio)")
    parser.add_argument(
        "-f",
        "--input-file=",
        dest="input_file",
        type=str,
        help="path to file with targets")
    
    parser.add_argument(
        "-o",
        "--output-file=",
        dest="output_file",
        type=str,
        help="path to file with results")
    
    parser.add_argument(
        "-p",
        "--port=",
        dest='port',
        type=int,
        default=CONST_DEFAULT_PORT,
        help=f"Specify port (default: {CONST_DEFAULT_PORT})")

    parser.add_argument(
        "--show-only-success",
        dest="show_only_success",
        action="store_true")

    parser.add_argument(
        "-s",
        "--senders=",
        dest="senders",
        type=int,
        default=CONST_C,
        help=f"Number of send coroutines to use (default: {CONST_C})")

    parser.add_argument(
        "-t",
        "--timeout=",
        dest='timeout',
        type=int,
        default=CONST_TIMEOUT,
        help=f"Timeout for connect to SSH (default: {CONST_TIMEOUT})")

    parser.add_argument(
        "--show-statistics",
        dest="statistics",
        action="store_true")

    settings = create_settings(parser.parse_args())

    if version_info >= (3, 11):
        with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
            runner.run(main(settings))
    else:
        uvloop.install()
        asyncio.run(main(settings))