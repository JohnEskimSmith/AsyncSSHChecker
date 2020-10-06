#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = "SAI"
__license__ = "GPLv3"
__status__ = "Dev"
from hashlib import md5, sha1, sha256, sha384, sha512
from aioconsole import ainput
from ipaddress import ip_address, ip_network
from collections import namedtuple
from aiofiles import open as aiofiles_open
from os import path
from ujson import dumps as ujson_dumps
import argparse
import datetime
import copy
import uvloop
import asyncio
import asyncssh

from base64 import (b64encode as base64_b64encode,
                    )


from typing import (Any,
                    NamedTuple,
                    Iterator,
                    BinaryIO,
                    TextIO,
                    )


def dict_paths(some_dict: dict,
               path: set = ()):
    """
    Итератор по ключам в словаре
    :param some_dict:
    :param path:
    :return:
    """
    for key, value in some_dict.items():
        key_path = path + (key,)
        yield key_path
        if hasattr(value, 'items'):
            yield from dict_paths(value, key_path)


def check_path(some_dict: dict,
               path_sting: str) -> bool:
    """
    Проверяет наличие ключа
    :param some_dict:
    :param path_sting:
    :return:
    """
    if isinstance(some_dict, dict):
        all_paths = set(['.'.join(p) for p in dict_paths(some_dict)])
        if path_sting in all_paths:
            return True


def return_value_from_dict(some_dict: dict,
                           path_string: str) -> Any:
    """
    Возвращает значение ключа в словаре по пути ключа "key.subkey.subsubkey"
    :param some_dict:
    :param path_string:
    :return:
    """
    if check_path(some_dict, path_string):
        keys = path_string.split('.')
        _c = some_dict.copy()
        for k in keys:
            _c = _c[k]
        return _c


def check_ip(ip_str: str) -> bool:
    """
    Проверка строки на ip адрес
    :param ip_str:
    :return:
    """
    try:
        ip_address(ip_str)
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
        ip_network(net_str)
        return True
    except BaseException:
        return False


def create_target_ssh_protocol(ip_str: str,
                               settings: dict) -> Iterator:
    """
    На основании ip адреса и настроек возвращает через yield
    экзэмпляр namedtuple - Target.
    Каждый экземпляр Target содержит всю необходимую информацию(настройки и параметры) для функции worker.
    :param ip_str:
    :param settings:
    :return:
    """
    current_settings = copy.copy(settings)
    key_names = list(current_settings.keys())
    key_names.extend(['ip', 'command'])
    Target = namedtuple('Target', key_names)
    current_settings['ip'] = ip_str
    current_settings['command'] = 'ls -la1'
    current_settings['ip'] = ip_str
    target = Target(**current_settings)
    yield target


def create_targets_ssh_protocol(ip_str: str,
                                settings: dict) -> Iterator[NamedTuple]:
    """
    Функция для обработки "подсетей" и создания "целей"
    :param ip_str:
    :param settings:
    :return:
    """
    hosts = ip_network(ip_str, strict=False)
    for host in hosts:
        for target in create_target_ssh_protocol(str(host), settings):
            yield target


def create_template_struct(target: NamedTuple) -> dict:
    """
    вспомогательная функция, создает шаблон словаря заданной в коде структуры
    :return:
    """
    result = {'data':
                  {'ssh':
                       {'status': 'ssh',
                        'result':
                            {'response':
                                 {'request': {}
                                  }
                             }
                        }
                   }
              }

    return result


def create_template_error(target: NamedTuple,
                          error_str: str) -> dict:
    """
    create template record, add error_str to record
    :param target:
    :param error_str:
    :return:
    """
    _tmp = {'ip': target.ip,
            'port': target.port,
            'data': {}}
    _tmp['data']['ssh'] = {'status': 'unknown-error',
                           'error': error_str}
    return _tmp


def make_document_from_response(buffer: bytes,
                                target: NamedTuple,
                                additions: dict = None) -> dict:
    """
    Обработка результата чтения байт из соединения
    - buffer - байты полученные от сервиса(из соединения)
    - target - информация о цели (какой порт, ip, payload и так далее)
    результат - словарь с результатом, который будет отправлен в stdout
    :param buffer:
    :param target:
    :return:
    """

    def update_line(json_record: dict,
                    target: NamedTuple) -> dict:
        """
        обновление записи (вспомогательная)
        :param json_record:
        :param target:
        :return:
        """
        json_record['ip'] = target.ip
        json_record['port'] = int(target.port)
        return json_record

    _default_record = create_template_struct(target)
    _default_record['data']['ssh']['status'] = "success"
    if buffer:
        _default_record['data']['ssh']['result']['response']['content_length'] = len(
            buffer)
    try:
        _default_record['data']['ssh']['result']['response']['request']['username'] = target.username
        _default_record['data']['ssh']['result']['response']['request']['password'] = target.password
    except:
        pass
    try:
        if buffer:
            _base64_data = base64_b64encode(buffer).decode('utf-8')
            _default_record['data']['ssh']['result']['response']['body_raw'] = _base64_data
    except Exception as e:
        pass
    if args.fingerprint:
        _default_record['data']['ssh']['result']['response'].pop("request")
    if additions:
        if isinstance(additions, dict):
            _default_record['data']['ssh']['result']['response'].update(additions)
    return update_line(_default_record, target)


async def _get_server_host_key(host, port=(), *, tunnel=(), family=(), flags=0,
                              local_addr=None, client_version=(), kex_algs=(),
                              server_host_key_algs=(), config=(), options=None):
    """Retrieve an SSH server's host key

       This is a coroutine which can be run to connect to an SSH server and
       return the server host key presented during the SSH handshake.

       A list of server host key algorithms can be provided to specify
       which host key types the server is allowed to choose from. If the
       key exchange is successful, the server host key sent during the
       handshake is returned.

           .. note:: Not all key exchange methods involve the server
                     presenting a host key. If something like GSS key
                     exchange is used without a server host key, this
                     method may return `None` even when the handshake
                     completes.

       :param host:
           The hostname or address to connect to
       :param port: (optional)
           The port number to connect to. If not specified, the default
           SSH port is used.
       :param tunnel: (optional)
           An existing SSH client connection that this new connection should
           be tunneled over. If set, a direct TCP/IP tunnel will be opened
           over this connection to the requested host and port rather than
           connecting directly via TCP. A string of the form
           [user@]host[:port] may also be specified, in which case a
           connection will first be made to that host and it will then be
           used as a tunnel.
       :param family: (optional)
           The address family to use when creating the socket. By default,
           the address family is automatically selected based on the host.
       :param flags: (optional)
           The flags to pass to getaddrinfo() when looking up the host address
       :param local_addr: (optional)
           The host and port to bind the socket to before connecting
       :param client_version: (optional)
           An ASCII string to advertise to the SSH server as the version of
           this client, defaulting to `'AsyncSSH'` and its version number.
       :param kex_algs: (optional)
           A list of allowed key exchange algorithms in the SSH handshake,
           taken from :ref:`key exchange algorithms <KexAlgs>`
       :param server_host_key_algs: (optional)
           A list of server host key algorithms to allow during the SSH
           handshake, taken from :ref:`server host key algorithms
           <PublicKeyAlgs>`.
       :param config: (optional)
           Paths to OpenSSH client configuration files to load. This
           configuration will be used as a fallback to override the
           defaults for settings which are not explcitly specified using
           AsyncSSH's configuration options. If no paths are specified,
           an attempt will be made to load the configuration from the file
           :file:`.ssh/config`. If this argument is explicitly set to
           `None`, no OpenSSH configuration files will be loaded. See
           :ref:`SupportedClientConfigOptions` for details on what
           configuration options are currently supported.
       :param options: (optional)
           Options to use when establishing the SSH client connection used
           to retrieve the server host key. These options can be specified
           either through this parameter or as direct keyword arguments to
           this function.
       :type host: `str`
       :type port: `int`
       :type tunnel: :class:`SSHClientConnection` or `str`
       :type family: `socket.AF_UNSPEC`, `socket.AF_INET`, or `socket.AF_INET6`
       :type flags: flags to pass to :meth:`getaddrinfo() <socket.getaddrinfo>`
       :type local_addr: tuple of `str` and `int`
       :type client_version: `str`
       :type kex_algs: `str` or `list` of `str`
       :type server_host_key_algs: `str` or `list` of `str`
       :type config: `list` of `str`
       :type options: :class:`SSHClientConnectionOptions`

       :returns: An :class:`SSHKey` public key or `None`

    """

    def conn_factory():
        """Return an SSH client connection factory"""

        return asyncssh.SSHClientConnection(loop, options, wait='kex')

    loop = asyncio.get_event_loop()

    options = asyncssh.SSHClientConnectionOptions(
        options, config=config, host=host, port=port, tunnel=tunnel,
        family=family, local_addr=local_addr, known_hosts=None,
        server_host_key_algs=server_host_key_algs, x509_trusted_certs=None,
        x509_trusted_cert_paths=None, x509_purposes='any', gss_host=None,
        kex_algs=kex_algs, client_version=client_version)

    conn = await asyncssh.connection._connect(options.host, options.port, loop, options.tunnel,
                          options.family, flags, options.local_addr,
                          conn_factory, 'Fetching server host key from')

    server_host_key = conn.get_server_host_key()
    try:
        server_version = conn.get_extra_info('server_version')
    except:
        server_version = ''
    conn.abort()

    await conn.wait_closed()
    return server_version, server_host_key


async def worker_single_run(target: NamedTuple,
                        semaphore: asyncio.Semaphore,
                        queue_out: asyncio.Queue) -> None:
    """
    сопрограмма, осуществляет подключение к Target,
    отправку и прием данных, формирует результата в виде dict
    :param target:
    :param semaphore:
    :return:
    """
    global count_good
    global count_error
    async with semaphore:
        result = None
        status_data = False
        key = None
        try:
            future_connection = asyncssh.connect(host=target.ip,
                                                 port=target.port,
                                                 username=target.username,
                                                 password=target.password,
                                                 known_hosts=None)
            conn = await asyncio.wait_for(future_connection, timeout=target.timeout_connection)
            async with conn:
                try:
                    _key = conn.get_server_host_key()
                    try:
                        server_version = conn.get_extra_info('server_version')
                    except:
                        server_version = ''

                    h_alg = _key.algorithm
                    h_alg = h_alg.decode('utf-8')
                    if h_alg == "ssh-rsa":
                        _key_hex = md5(_key.public_data).hexdigest()
                        key = {h_alg: {'md5': _key_hex}}
                    else:
                        _key_hex = sha256(_key.public_data).hexdigest()
                        key = {h_alg: {'sha256': _key_hex}}
                except:
                    pass
                try:
                    _result = await conn.run(target.command, check=True, timeout=target.timeout_read)
                    result_data_str = _result.stdout
                    status_data = True  # trivial check that's all Ok? need rethink
                except Exception as e:
                    result = create_template_error(target, str(e))
                    await asyncio.sleep(0.005)
        except Exception as e:
            result = create_template_error(target, str(e))
            await asyncio.sleep(0.005)
        if status_data:
            try:
                result = result_data_str.encode('utf-8')
            except:
                result = b'all good, but not command'
            add_info = None
            if key:
                add_info = {'fingerprint': []}
                add_info['fingerprint'].append(key)
                if server_version:
                    add_info['version'] = server_version
            result = make_document_from_response(
                result, target, add_info)
        if result:
            success = return_value_from_dict(result, "data.ssh.status")
            if success == "success":
                count_good += 1
            else:
                count_error += 1
            line = None
            try:
                if args.show_only_success:
                    if success == "success":
                        line = ujson_dumps(result)
                else:
                    line = ujson_dumps(result)
            except Exception as e:
                pass
            if line:
                await queue_out.put(line)


async def worker_single_fingerprint(target: NamedTuple,
                        semaphore: asyncio.Semaphore,
                        queue_out: asyncio.Queue) -> None:
    global count_good
    global count_error
    async with semaphore:
        result = None
        _results = []
        for algorithm in target.algorithms:
            status = False
            key = None
            try:
                if algorithm != 'host':
                    future_connection = _get_server_host_key(host=target.ip,
                                                                     port=target.port,
                                                                     server_host_key_algs=algorithm,
                                                                     client_version='AsyncSSHChecker')
                    status = True

                elif algorithm == 'host':
                    future_connection = _get_server_host_key(host=target.ip,
                                                                     port=target.port,
                                                                     client_version='AsyncSSHChecker')
                    status = True

                if status:
                    server_version, key = await asyncio.wait_for(future_connection, timeout=target.timeout_connection)

                if key:
                    function_hash = default_host_key_algorithms[algorithm]
                    function_hash_name = default_host_key_algorithms[algorithm].__name__
                    function_hash_name = function_hash_name.replace('openssl_', '')
                    _key_hex = function_hash(key.public_data).hexdigest()

                    # key_md5 = ':'.join(_key_md5[i:i + 2] for i in range(0, len(_key_md5), 2))
                    if algorithm == 'host':
                        _current_algorithm = key.algorithm
                        current_algorithm = _current_algorithm.decode('utf-8')
                    else:
                        current_algorithm = algorithm

                    _results.append({current_algorithm: {function_hash_name:_key_hex}})
            except:
                pass
        if _results:
            result = b''
            add_info = {'fingerprint': _results}
            if server_version:
                add_info['version'] = server_version
            result = make_document_from_response(
                result, target, add_info)
        else:
            result = create_template_error(target, 'no results')
            await asyncio.sleep(0.005)
        if result:
            success = return_value_from_dict(result, "data.ssh.status")
            if success == "success":
                count_good += 1
            else:
                count_error += 1
            line = None
            try:
                if args.show_only_success:
                    if success == "success":
                        line = ujson_dumps(result)
                else:
                    line = ujson_dumps(result)
            except Exception as e:
                pass
            if line:
                await queue_out.put(line)


async def write_to_stdout(object_file: BinaryIO,
                          record_str: str):
    """
    write in 'wb' mode to object_file, input string in utf-8
    :param object_file:
    :param record_str:
    :return:
    """
    await object_file.write(record_str.encode('utf-8') + b'\n')


async def write_to_file(object_file: TextIO,
                        record_str: str):
    """
    write in 'text' mode to object_file
    :param object_file:
    :param record_str:
    :return:
    """
    await object_file.write(record_str + '\n')


async def work_with_create_tasks_queue(queue_with_input: asyncio.Queue,
                                      queue_with_tasks: asyncio.Queue,
                                      queue_out: asyncio.Queue,
                                      count: int) -> None:
    """

    :param queue_with_input:
    :param queue_with_tasks:
    :param queue_out:
    :param count:
    :return:
    """
    semaphore = asyncio.Semaphore(count)
    while True:
        item = await queue_with_input.get()  # item Target
        if item == b"check for end":
            await queue_with_tasks.put(b"check for end")
            break
        if item:
            if not args.fingerprint:
                _task = worker_single_run(item, semaphore, queue_out)
            else:
                _task = worker_single_fingerprint(item, semaphore, queue_out)
            task = asyncio.create_task(_task)
            await queue_with_tasks.put(task)


async def work_with_queue_tasks(queue_results: asyncio.Queue,
                                queue_prints: asyncio.Queue) -> None:
    """

    :param queue_results:
    :param queue_prints:
    :return:
    """
    while True:
        # wait for an item from the "start_application"
        task = await queue_results.get()
        if task == b"check for end":
            await queue_prints.put(b"check for end")
            break
        if task:
            # try:
            await task
            # except:
            #     pass


async def work_with_queue_result(queue_out: asyncio.Queue,
                                 filename,
                                 mode_write) -> None:
    """

    :param queue_out:
    :param filename:
    :param mode_write:
    :return:
    """
    if mode_write == 'a':
        method_write_result = write_to_file
    else:
        method_write_result = write_to_stdout
    async with aiofiles_open(filename, mode=mode_write) as file_with_results:
        while True:
            line = await queue_out.get()
            if line == b"check for end":
                break
            if line:
                await method_write_result(file_with_results, line)
    await asyncio.sleep(0.5)
    # region dev
    if args.statistics:
        stop_time = datetime.datetime.now()
        _delta_time = stop_time - start_time
        duration_time_sec = _delta_time.total_seconds()
        statistics = {'duration': duration_time_sec,
                      'valid targets': count_input,
                      'success': count_good,
                      'fails': count_error}
        async with aiofiles_open('/dev/stdout', mode='wb') as stats:
            await stats.write(ujson_dumps(statistics).encode('utf-8') + b'\n')
    # endregion


async def read_input_file(queue_input: asyncio.Queue,
                          settings: dict,
                          path_to_file: str) -> None:
    """
    посредством модуля aiofiles функция "асинхронно" читает из файла записи, представляющие собой
    обязательно или ip адрес или запись подсети в ipv4
    из данной записи формируется экзэмпляр NamedTuple - Target, который отправляется в Очередь
    :param queue_results:
    :param settings:
    :param path_to_file:
    :return:
    """
    global count_input
    async with aiofiles_open(path_to_file, mode='rt') as f:  # read str
        async for line in f:
            linein = line.strip()
            if any([check_ip(linein), check_network(linein)]):
                targets = create_targets_ssh_protocol(linein, settings) # generator
                if targets:
                    for target in targets:
                        check_queue = True
                        while check_queue:
                            size_queue = queue_input.qsize()
                            if size_queue < queue_limit_targets-1:
                                count_input += 1  # statistics
                                queue_input.put_nowait(target)
                                check_queue = False
                            else:
                                await asyncio.sleep(sleep_duration_queue_full)


    await queue_input.put(b"check for end")


async def read_input_stdin(queue_input: asyncio.Queue,
                           settings: dict,
                           path_to_file: str = None) -> None:
    """
        посредством модуля aioconsole функция "асинхронно" читает из stdin записи, представляющие собой
        обязательно или ip адрес или запись подсети в ipv4
        из данной записи формируется экзэмпляр NamedTuple - Target, который отправляется в Очередь
        TODO: использовать один модуль - или aioconsole или aiofiles
        :param queue_results:
        :param settings:
        :param path_to_file:
        :return:
        """
    global count_input
    while True:
        try:
            _tmp_input = await ainput()  # read str from stdin
            linein = _tmp_input.strip()
            if any([check_ip(linein), check_network(linein)]):
                targets = create_targets_ssh_protocol(linein, settings)
                if targets:
                    for target in targets:
                        check_queue = True
                        while check_queue:
                            size_queue = queue_input.qsize()
                            if size_queue < queue_limit_targets - 1:
                                count_input += 1  # statistics
                                queue_input.put_nowait(target)
                                check_queue = False
                            else:
                                await asyncio.sleep(sleep_duration_queue_full)
        except EOFError:
            await queue_input.put(b"check for end")
            break


def checkfile(path_to_file: str) -> bool:
    return path.isfile(path_to_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Async SSH checker lite(asyncio)')
    parser.add_argument(
        "-settings",
        type=str,
        help="path to file with settings(yaml)")


    parser.add_argument(
        "-f",
        "--input-file=",
        dest='input_file',
        type=str,
        help="path to file with targets")

    parser.add_argument(
        "-o",
        "--output-file=",
        dest='output_file',
        type=str,
        help="path to file with results")

    parser.add_argument(
        "-s",
        "--senders=",
        dest='senders',
        type=int,
        default=256,
        help="Number of send coroutines to use (default: 256)")

    parser.add_argument(
        "--queue-sleep=",
        dest='queue_sleep',
        type=int,
        default=1,
        help='Sleep duration if the queue is full, default 1 sec. Size queue == senders')

    parser.add_argument(
        '--fingerprint-host-key-algorithms=',
        dest='fingerprint',
        type=str,
        help='Only fingerprint SSH. Set SSH Host Key Algorithms (default: ssh-rsa). host-key-algorithms in '
             'ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519 or host')


    parser.add_argument(
        "-tconnect",
        "--timeout-connection=",
        dest='timeout_connection',
        type=int,
        default=2,
        help='Set connection timeout for open_connection (default: 7)')

    parser.add_argument(
        "-tread",
        "--timeout-read=",
        dest='timeout_read',
        type=int,
        default=2,
        help='Set connection timeout for reader from connection (default: 7)')

    parser.add_argument(
        "-p",
        "--port=",
        dest='port',
        type=int,
        default=22,
        help='Specify port (default: 22)')

    parser.add_argument(
        '--show-only-success',
        dest='show_only_success',
        action='store_true')
    # endregion

    parser.add_argument("--user=", dest='single_user', type=str,
                        help='single username')

    parser.add_argument("--password=", dest='single_password', type=str,
                        help='single password')

    parser.add_argument(
        '--show-statistics',
        dest='statistics',
        action='store_true')

    path_to_file_targets = None  # set default None to inputfile
    args = parser.parse_args()
    if args.settings:
        pass  # TODO реализовать позднее чтение настроек из файла
    else:
        # region parser ARGs
        if not args.port:
            print('Exit, port?')
            exit(1)
        # в method_create_targets - метод, которые или читает из stdin или из
        # файла
        if not args.input_file:
            # set method - async read from stdin (str)
            method_create_targets = read_input_stdin
        else:
            # set method - async read from file(txt, str)
            method_create_targets = read_input_file

            path_to_file_targets = args.input_file
            if not checkfile(path_to_file_targets):
                print(f'ERROR: file not found: {path_to_file_targets}')
                exit(1)

        if not args.output_file:
            output_file, mode_write = '/dev/stdout', 'wb'
        else:
            output_file, mode_write = args.output_file, 'a'

        # endregion

    time_out_for_connection = args.timeout_connection

    settings = {'port': args.port,
                'timeout_connection': args.timeout_connection,
                'timeout_read': args.timeout_read}
    if not args.fingerprint:
        try:
            _settings = {
                        'username': args.single_user,
                        'password': args.single_password
                        }
            settings.update(_settings)
        except:
            print('Exit, username, passwords?')
            exit(1)
    else:
        default_host_key_algorithms = {'ssh-rsa': md5, 'ecdsa-sha2-nistp256': sha256,
                                       'ssh-ed25519': sha256, 'host': sha256}
        _default_algorithms = ['ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519', 'host']
        algorithms = []
        if ',' in args.fingerprint:
            algorithms = [alg for alg in args.fingerprint.split(',') if alg in  _default_algorithms]
            if not algorithms:
                print('Exit, error with host key algorithms?')
                exit(1)
        else:
            if args.fingerprint == 'ssh-rsa':
                algorithms = ['ssh-rsa']
            elif args.fingerprint in _default_algorithms:
                algorithms = [args.fingerprint]
        if not algorithms:
            print('Exit, error with host key algorithms?')
            exit(1)
        else:
            _settings = {
                        'algorithms': algorithms
                        }
            settings.update(_settings)

    count_cor = args.senders
    # region limits input Queue
    queue_limit_targets = count_cor
    sleep_duration_queue_full = args.queue_sleep
    # endregion
    count_input = 0
    count_good = 0
    count_error = 0
    start_time = datetime.datetime.now()
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = asyncio.get_event_loop()
    queue_input = asyncio.Queue()
    queue_results = asyncio.Queue()
    queue_prints = asyncio.Queue()
    read_input = method_create_targets(queue_input, settings, path_to_file_targets)  # create targets
    create_tasks = work_with_create_tasks_queue(queue_input, queue_results, queue_prints, count_cor)  # execution
    execute_tasks = work_with_queue_tasks(queue_results, queue_prints)
    print_output = work_with_queue_result(queue_prints, output_file, mode_write)
    loop.run_until_complete(
        asyncio.gather(
            read_input,
            create_tasks,
            execute_tasks,
            print_output))
    loop.close()
