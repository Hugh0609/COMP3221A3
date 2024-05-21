from cryptography.exceptions import InvalidSignature
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from enum import Enum
import hashlib
import json
import re

sender_valid = re.compile('^[a-fA-F0-9]{64}$')
signature_valid = re.compile('^[a-fA-F0-9]{128}$')

TransactionValidationError = Enum('TransactionValidationError', ['INVALID_JSON', 'INVALID_SENDER', 'INVALID_MESSAGE', 'INVALID_SIGNATURE',"INVALID_NONCE"])



def make_transaction(sender, message, nonce, signature) -> str:
		return json.dumps({"type":"transaction","payload":{'sender': sender, 'message': message,"nonce":nonce, 'signature': signature}},sort_keys = True)



def make_block_proposal(index,transactions,previous_hash,current_hash):
	return json.dumps({"index":index,"transactions":transactions,"previous_hash":previous_hash,"current_hash":current_hash},sort_keys=True)



def convert_to_hash(json_object):
	return hashlib.sha256(json_object.encode("utf-8")).hexdigest()


def transaction_bytes(transaction: dict) -> bytes:
	return json.dumps({k: transaction.get(k) for k in ['sender', 'message',"nonce"]}, sort_keys=True).encode("utf-8")


def make_signature(private_key: ed25519.Ed25519PrivateKey, message: str, nonce: int) -> str:
	transaction = {'sender': private_key.public_key().public_bytes_raw().hex(), 'message': message,"nonce" : nonce}
	return private_key.sign(transaction_bytes(transaction)).hex()

# Take a json object and 
def validate_transaction(transaction: dict,blockchain) -> dict :
	tx = transaction 

	if not(tx.get('sender') and isinstance(tx['sender'], str) and sender_valid.search(tx['sender'])):
		print(f"[TX] Received an invalid transaction, wrong sender - {tx['message']}")
		return TransactionValidationError.INVALID_SENDER

	if not(tx.get('message') and isinstance(tx['message'], str) and len(tx['message']) <= 70 and tx['message'].isalnum()):
		print(f"[TX] Received an invalid transaction, wrong message - {tx['message']}")
		return TransactionValidationError.INVALID_MESSAGE


	if not tx.get("nonce") or not isinstance(tx["nonce"],int):
		print(f"[TX] Received an invalid transaction, wrong nonce - {tx['message']}")
		return TransactionValidationError.INVALID_NONCE


	# Check that if we have received a nonce from the sender, that it is at least larger than previous nonce. 
	if (tx["sender"] in blockchain.nonces and tx["nonce"]<= blockchain.nonces[tx["sender"]]):
		print(f"[TX] Received an invalid transaction, wrong nonce - {tx['message']}")
		return TransactionValidationError.INVALID_NONCE

	# Check if we already have a transaction with the same sender / nonces. 
	for i in range(0,len(blockchain.pool)):
		if blockchain.pool[i]["sender"] == tx["sender"] and blockchain.pool[i]["nonce"] == tx["nonce"]:
			print(f"[TX] Received an invalid transaction, wrong nonce - {tx['message']}")
			return TransactionValidationError.INVALID_NONCE

	public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx['sender']))
	if not(tx.get('signature') and isinstance(tx['signature'], str) and signature_valid.search(tx['signature'])):
		print(f"[TX] Received an invalid transaction, wrong signature mssage - {tx['message']}")

		return TransactionValidationError.INVALID_SIGNATURE
	try:
		public_key.verify(bytes.fromhex(tx['signature']), transaction_bytes(tx))
	except InvalidSignature:
		print(f"[TX] Received an invalid transaction, wrong signature mssage - {tx['message']}")

		return TransactionValidationError.INVALID_SIGNATURE
	
	return tx






class Blockchain():
	def  __init__(self):
		self.blockchain = []
		self.pool = []
		self.nonces = {}
		self.connected_outgoing_nodes = 0


		self.consensus = False
		self.proposals = []
		self.finished_nodes = 0 
		self.rounds_total = 1


		# Genesis Block
		self.blockchain.append(
			{
			"index": 0,
			"transactions": [],
			"previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
			"current_hash": "03525042c7132a2ec3db14b7aa1db816e61f1311199ae2a31f3ad1c4312047d1"
			}
		)

	def create_proposal(self,index):
		# Only create a block proposal if we have at least one transaction. 
		if not self.pool:
			return []



		block = {
			"index" : index,
			"transactions" : self.pool,
			"previous_hash" :  self.blockchain[-1]["current_hash"]
		}
		self.pool = []

		block["current_hash"] = self.calculate_hash(block)
		self.proposals.append(block)
		return block



	def new_block(self, previous_hash=None):
		block = {
			'index': len(self.blockchain) + 1,
			'transactions': self.pool,
			'previous_hash': previous_hash or self.blockchain[-1]['current_hash'],
		}
		block['current_hash'] = self.calculate_hash(block)
		self.pool = []
		self.blockchain.append(block)

	def last_block(self):
		return self.blockchain[-1]

# Tutorial solution
	def calculate_hash(self, block: dict) -> str:
		block_object: str = json.dumps({k: block.get(k) for k in ['index', 'transactions', 'previous_hash']}, sort_keys=True)
		block_string = block_object.encode()
		raw_hash = hashlib.sha256(block_string)
		hex_hash = raw_hash.hexdigest()
		return hex_hash




	def add_transaction(self, transaction) -> bool:
		
		self.nonces[transaction["sender"]] = transaction["nonce"]

		self.pool.append(transaction)
		print(f"[MEM] Stored transaction in the transaction pool: {transaction['signature']}")
