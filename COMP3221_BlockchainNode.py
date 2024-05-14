import sys
import socket
import socketserver
from threading import Lock
import json
from blockchain_support import *

from blockchain import Blockchain
from network import recv_prefixed, send_prefixed
import threading





if __name__ == "__main__":
    
    port_num = int(sys.argv[1])
    node_list = sys.argv[2]
    
    host = "127.0.0.1"

    blockchain_obj = Blockchain()


    server_port_pairs = read_node_list(node_list)
    
    tcp_thread = threading.Thread(target = run_TCP,args = (host, port_num, blockchain_obj))
    tcp_thread.start()

    outgoing_connections = threading.Thread(target = establish_connections, args= (server_port_pairs,blockchain_obj))
    outgoing_connections.start()
    
