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


def main():
    q = queue.Queue()
    config = _read_config()
    logger = _build_logger()
    port_and_ip = _input_port_ip()

    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(tcp_server, port_and_ip[0], port_and_ip[1], config[4], logger, q)
        executor.submit(heartbeat_monitor, port_and_ip[0], port_and_ip[1], config[1], config[2], logger, q)


def tcp_server(ip, port, data_threshold, logger, q):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_response = b"SERVER_DATA_REPLY"

    while True:
        try:
            server.bind((ip, int(port)))
            break

        except WindowsError as e:
            if e.winerror == 10049:
                logger.warning(f"Thread 1: Server IP of {ip} is invalid when establishing socket. Check interface IP Address")
                sleep(1)

        port_and_ip = _input_port_ip()
        ip, port = port_and_ip[0], port_and_ip[1]

    server.listen()
    logger.info(f"Thread 1: TCP Server is Listening on {ip}:{port}")

    client, address = server.accept()
    logger.info(f"Thread 1: Accepted connection from {address[0]}:{address[1]}")

    with client:
        client.settimeout(int(data_threshold))

        while True:
            try:
                request = client.recv(1024).decode('utf-8')
                if not request: # Testing paragraph 3. If the client disconnects b/c it didn't recieve a reply, switches to heartbeat
                    logger.warning(f"Thread 1: No client message detected in {data_threshold} seconds. "
                                   f"Initiating Heartbeat Server")
                    q.put(server)
                    break
                # client.sendall(server_response)  - Testing Paragraph 3. If the client does not get a msg from the svr
                logger.info(f"Thread 1: Received client data: '{request}'. Sent Server Data: '{server_response}'")

            except socket.timeout:
                logger.error(f"Thread 1: No client message detected in {data_threshold} seconds. Initiating Heartbeat "
                             f"Server")
                q.put(server)
                break

def heartbeat_monitor(ip, port, hbeat_threshold, hbeat_additional, logger, q):
    server = q.get()

    server.listen()
    logger.info(f"Thread 2: TCP Server is Listening for Heartbeat on {ip}:{port}")

    client, address = server.accept()
    logger.info(f"Thread 2: Accepted connection from {address[0]}:{address[1]}")

    heartbeats_missed = 0

    with client:
        client.settimeout(int(hbeat_threshold))

        while True:
            try:
                request = client.recv(1024).decode('utf-8')
                if not request:
                    break
                client.sendall(request) # Test 3rd to last paragraph
                logger.info(f"Thread 2: Received Heartbeat from Client: '{request}'. Echoing {request} back to client")

            except socket.timeout:
                heartbeats_missed += 1
                logger.warning(f"Thread 2: No heartbeat recieved in {hbeat_threshold} seconds. Heartbeats missed: "
                               f"{heartbeats_missed}")
                if heartbeats_missed == int(hbeat_additional):
                    break

    logger.error(f"Thread 2: Missed {int(hbeat_additional)} heartbeats from client. Terminating connection")


def _input_port_ip():
    server_ip = input("Enter IP Address for the listening interface for this TCP Server: ")
    while not _validate_ip(server_ip):
        server_ip = input("Invalid IP Address. Please specify a valid IP i.e. 192.168.0.10: ")

    listening_port = input("Enter the Port this TCP Server will listen on: ")
    while not _validate_port(listening_port):
        listening_port = input("Invalid port number. Please specify a valid port between 1-65535: ")

    return server_ip, listening_port


def _read_config():
    config = configparser.ConfigParser()
    config.read(r'config.txt')

    heartbeat_interval = config['Settings']['heart_beat_interval']
    heartbeat_threshold = config['Settings']['heart_beat_threshold']
    heartbeat_additional_beats = config['Settings']['heart_beat_additional_tries']

    data_interval = config['Settings']['data_interval']
    data_threshold = config['Settings']['data_threshold']

    return heartbeat_interval, heartbeat_threshold, heartbeat_additional_beats, data_interval, data_threshold


def _build_logger():
    """ Build Logger for the program """
    directory = os.path.dirname(os.path.abspath(__file__))
    os.chdir(directory)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    file_handler_info = RotatingFileHandler('../logs/server/TCPServer_info.log', maxBytes=1048576)
    file_handler_warning = RotatingFileHandler('../logs/server/TCPServer_warning.log', maxBytes=1048576)
    file_handler_error = RotatingFileHandler('../logs/server/TCPServer_error.log', maxBytes=1048576)
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


def _validate_port(port):
    regex = re.compile(r'(\d)+')
    if regex.fullmatch(port) and 1 <= int(port) <= 65535:
        return True
    return False


def _validate_ip(ip):
    regex = re.compile(r"""
                        \b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3} # Match first 3 ocetets
                        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b          # Match final octet. No period at end
                        """, re.VERBOSE)
    if regex.search(ip):
        return True
    return False


if __name__ == '__main__':
    main()
