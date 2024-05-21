import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
import socket
import time

from blockchain import make_signature, make_transaction
from network import recv_prefixed, send_prefixed
import json


#request = json.dumps({"type":"values","payload":index},sort_keys = True)


nonce = 1
index = 1

private_key = ed25519.Ed25519PrivateKey.generate()
sender = private_key.public_key().public_bytes_raw().hex()
message = 'meoMEOWTHw'
signature = make_signature(private_key, message,nonce)
transaction = make_transaction(sender, message,nonce, signature)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 8000))


msg = json.dumps({"type":"transaction","payload":transaction},sort_keys=True)


# nonce+=1
# message = 'y'
# signature = make_signature(private_key, message,nonce)
# transaction = make_transaction(sender, message,nonce, signature)

# s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s2.connect(('localhost', 9000))


# msg2 = json.dumps({"type":"transaction","payload":transaction},sort_keys=True)


# send_prefixed(s2,msg2.encode())


send_prefixed(s, msg.encode())

try:
	data = recv_prefixed(s).decode()
	print(data)
	# data = recv_prefixed(s2).decode()
	print(data)
except Exception as e:
	print(e)


