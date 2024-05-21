import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
import socket
import time

from blockchain import make_signature, make_transaction
from network import recv_prefixed, send_prefixed

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(("localhost",7000))
s.listen(2)
con = 0
while True:
    clientsocket,address = s.accept()
    if clientsocket:
        con+=1
    if con == 2:
        break

time.sleep(10)
