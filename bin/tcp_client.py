import configparser
import logging
import os
import queue
import re
import socket
import sys

from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from time import sleep

#TODO: Termination message

def main():
    """ Build Logger. Get validated IP and Port Number of TCP Server. Read parameters from configuration file.
    Save parameters into arguments and pass arguments to respective threads for Data Message and Heartbeat """
    q = queue.Queue()
    config = _read_config()
    logger = _build_logger()
    port_and_ip = _input_port_ip()

    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(tcp_client, port_and_ip[0], port_and_ip[1], config[3], config[4], logger, q)
        executor.submit(heartbeat_monitor, port_and_ip[0], port_and_ip[1], config[0], config[1], config[2], logger, q)


def tcp_client(ip, port, data_interval, data_threshold, logger, q):
    """ Create socket with appropriate timeout and connect to TCP Server. Send data to TCP Server
    in an interval (seconds) determined by the data_interval parameter """

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(int(data_threshold))
    client_data = b'CLIENT_DATA_MESSAGE'

    while True:
        try:
            client.connect((ip, int(port)))
            logger.info(f"Thread 1: Client successfully connected to Server at {ip}:{port}")
            break

        except socket.timeout:
            logger.warning(f"Thread 1: Client failed to find IP Address {ip}")
            sleep(1)

        except WindowsError as e:
            if e.winerror == 10061:
                logger.warning(f"Thread 1: {ip} was located but connection was actively refused on port {port}")
                sleep(1)

        except Exception as e:
            logger.warning(f"Thread 1: Error when connecting to server: {e}")
            sleep(1)

        port_and_ip = _input_port_ip()
        ip, port = port_and_ip[0], port_and_ip[1]

    with client:
        while True:
            client.sendall(client_data)
            # sleep(30) # Testing Paragraph 3 if the client does not send a msg to svr
            logger.info(f"Thread 1: Client sent data: {client_data}")

            try:
                response = client.recv(4096)
                logger.info(f"Thread 1: Successful Tx/Rx. Client sent: '{client_data}' Server replied: '{response.decode()}'")
                print(f"Sleeping {data_interval} seconds until next data transfer...")
                sleep(int(data_interval))
                # if termination message; break

            except socket.timeout:  # Testing paragraph 3 if the client does not recieve a msg from svr
                logger.error(f"Thread 1: Did not receive a reply from server in {data_threshold} seconds. Initating Heartbeat")
                q.put(True)
                break


def heartbeat_monitor(ip, port, hbeat_interval, hbeat_threshold, hbeat_additional, logger, q):
    while True:
        try:
            q.get(timeout=5)
            break
        except queue.Empty:
            continue

    sleep(5) # Ensure that the server-side heartbeat is running first before continuing
    hbeat_additional_int = int(hbeat_additional) + 1

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(int(hbeat_threshold))
    client_heartbeat_data = b"MSG_HEARTBEAT"
    client.connect((ip, int(port)))

    with client:
        while True:
            sleep(500) # Test 2nd to last paragraph
            client.sendall(client_heartbeat_data)
            logger.info(f"Thread 2: Client sent heatbeat: {client_heartbeat_data}")

            try:
                response = client.recv(4096)
                logger.info(f"Thread 2: Successful Tx/Rx. Client sent: '{client_heartbeat_data}' Server replied: "
                            f"'{response.decode()}'")
                print(f"Sleeping {hbeat_interval} seconds until next heartbeat transfer...")
                sleep(int(hbeat_interval))
                # if termination message; break

            except socket.timeout:
                hbeat_additional_int -= 1
                if hbeat_additional_int == 0:
                    break
                logger.warning(f"Thread 2: No heartbeat received from server in {hbeat_threshold} seconds. "
                               f"Will try {hbeat_additional_int} more attempt(s)")

    logger.error(f"Thread 2: No replies from server after {hbeat_additional} attempts. Terminating connection")


def _input_port_ip():
    server_ip = input("Enter the IP Address of TCP Server to Connect to: ")
    while not _validate_ip(server_ip):
        server_ip = input("Invalid IP Address. Please specify a valid IP i.e. 192.168.0.10: ")

    target_port = input("Enter Target Port to Connect to on TCP Server: ")
    while not _validate_port(target_port):
        target_port = input("Invalid port number. Please specify a valid port between 1-65535: ")

    return server_ip, target_port


def _build_logger():
    """ Build Logger for the program """
    directory = os.path.dirname(os.path.abspath(__file__))
    os.chdir(directory)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    file_handler_info = RotatingFileHandler('../logs/client/TCPClient_info.log', maxBytes=1048576)
    file_handler_warning = RotatingFileHandler('../logs/client/TCPClient_warning.log', maxBytes=1048576)
    file_handler_error = RotatingFileHandler('../logs/client/TCPClient_error.log', maxBytes=1048576)
    stream_handler = logging.StreamHandler(stream=sys.stdout)

    file_handler_info.setLevel(logging.INFO)
    file_handler_warning.setLevel(logging.WARNING)
    file_handler_error.setLevel(logging.ERROR)
    stream_handler.setLevel(logging.DEBUG)

    handlers = [file_handler_info, file_handler_warning, file_handler_error, stream_handler]
    formatter = logging.Formatter('%(asctime)s || %(levelname)s || %(message)s || %(name)s')

    for handler in handlers:
        logger.addHandler(handler)
        handler.setFormatter(formatter)

    return logger


def _read_config():
    """ Reads parameters from config file """
    config = configparser.ConfigParser()
    config.read(r'config.txt')

    heartbeat_interval = config['Settings']['heart_beat_interval']
    heartbeat_threshold = config['Settings']['heart_beat_threshold']
    heartbeat_additional_beats = config['Settings']['heart_beat_additional_tries']

    data_interval = config['Settings']['data_interval']
    data_threshold = config['Settings']['data_threshold']

    return heartbeat_interval, heartbeat_threshold, heartbeat_additional_beats, data_interval, data_threshold


def _validate_port(port):
    """Ensure valid port number via regex"""
    regex = re.compile(r'(\d)+')
    if regex.fullmatch(port) and 1 <= int(port) <= 65535:
        return True
    return False


def _validate_ip(ip):
    """Ensure valid IP Address via regex"""
    regex = re.compile(r"""
                        \b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3} # Match first 3 ocetets
                        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b          # Match final octet. No period at end
                        """, re.VERBOSE)
    if regex.search(ip):
        return True
    return False


if __name__ == '__main__':
    main()
