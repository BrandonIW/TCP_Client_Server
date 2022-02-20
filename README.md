# What is TCP Client/Server?
This program runs in Python 3.9 and is split into 2 components. There is source code for both the TCP Client and the TCP Server. The program functions by first building a TCP Session between both Client and Server. The server will listen for incoming data packets from the client machine and send a confirmation message back to the client when it receives data. The server will also timeout after a user-specified amount of time (in seconds) if no data packets are received. 

The Client functions by sending data messages to the Server at a user-defined interval (in seconds) and receiving the Server’s replies. However, if either the Client or Server do not receive any data messages in a user-defined amount of time (in seconds) then both programs (Client and Server) will transition to another Thread which initiates a Heartbeat Protocol. 

The Heartbeat Protocol functions by way of a Heartbeat message that is sent and responded to between Server and Client. If either side does not receive a reply to a user-defined number of Heartbeat messages, the TCP connection will terminate. 

The program takes arguments through a configuration file that is read from within the program. 


## Compatability
Runs on Python 3.9

Currently uses IPTABLES for rules, so the server running the Script must be a Unix System.

## Configuration File
heart_beat_interval = 5         # Number of seconds between the client’s heartbeat messages

heart_beat_threshold = 10       # Number of seconds until a heartbeat message is considered to have timed out and was not received by the Server

heart_beat_additional_tries = 3 # Number of additional heartbeats the client will send after the heartbeat threshold/timeout has been reached

data_interval = 5               # Number of seconds between the client’s data messages

data_threshold = 20             # Number of seconds until a data message is considered to have timed out and was not received by the Server

## Quickstart
Windows:

1. Download .ZIP File (https://github.com/BrandonIW/TCP_Client_Server) & unpack
2. The client folder must be placed on the machine that will be acting as the client, and likewise for the server. 

Linux:

1. git clone https://github.com/BrandonIW/TCP_Client_Server.git
2. The client folder must be placed on the machine that will be acting as the client, and likewise for the server.

Note:

Ideally, both client and server should be different machines on the network, however the loopback address can also be used to test the application. It may also be necessary to open the port on the Server machine that you will be using for the TCP Connection. If the client cannot connect, but the IP is reachable, please check firewall rules

