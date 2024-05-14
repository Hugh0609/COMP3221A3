import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
import socket
import time

from blockchain import make_signature, make_transaction
from network import recv_prefixed, send_prefixed
import json

private_key = ed25519.Ed25519PrivateKey.generate()
sender = private_key.public_key().public_bytes_raw().hex()
message = 'hello'
signature = make_signature(private_key, message,1)
transaction = make_transaction(sender, message,1, signature)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 8000))

request = json.dumps({"type":"values","payload":1},sort_keys = True)



msg = json.dumps({"type":"transaction","payload":transaction},sort_keys=True)


send_prefixed(s, msg.encode())

try:
	data = recv_prefixed(s).decode()
	print(data)
except Exception as e:
	print(e)

time.sleep(1)
