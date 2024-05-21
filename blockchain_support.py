import socketserver
from threading import Lock
import json

from network import recv_prefixed, send_prefixed
import threading
import socket
import time
from blockchain import *
import sys


# Simple function to get hosts & port pairs.
def read_node_list(txt_file):
    server_port_pairs = []

    try: 
        with open(txt_file,"r") as f:
            for line in f:
                line = line.strip("\n")
                line = line.split(":")
                server_port_pairs.append((line[0],int(line[1])))
    except Exception:
        raise Exception(f"Error loading txt file {txt_file}")

    return server_port_pairs


# Class for TCP server. (Recieving data & sending replies.)
class MyTCPServer(socketserver.ThreadingTCPServer):
	def __init__(self, server_address, RequestHandlerClass, blockchain, bind_and_activate=True):
		self.blockchain = blockchain
		self.blockchain_lock = Lock()
		RequestHandlerClass.blockchain = blockchain
		super().__init__(server_address, RequestHandlerClass, bind_and_activate)

class MyTCPHandler(socketserver.BaseRequestHandler):
	server: MyTCPServer

    # Will handle any data sent to the server.
	def handle(self):
		while True:
			try:
				data = recv_prefixed(self.request).decode()
			except:
				break

			# Try load data.
			try:
				data = json.loads(data)
			except:
				# Send back response false.
				send_prefixed(self.request,json.dumps({"response":False}).enocde())



			if data["type"] == "transaction":
				# We only need the payload now.
				data = json.loads(data["payload"])
				data = data["payload"]

				# Received a transaction.
				print(f"[NET] Received a transaction from node {self.client_address[0]} : {data['message']}")

				# Validate the transaction.
				data = validate_transaction(transaction=data,blockchain=self.blockchain)
				# If the data is not a valid transaction we send a false response. 
				if not isinstance(data,dict):
					
					send_prefixed(self.request,json.dumps({"response":False}).encode())
				
				# If we have reached this point then the message is valid. 
				else:
					send_prefixed(self.request,json.dumps({"response":True}).encode())
					# Update the nonce. 
					self.blockchain.add_transaction(data)

					# If we have recieved a transaction and not in consensus, we need to create a proposal and send it. 
					if not self.blockchain.consensus:

						proposal = self.blockchain.create_proposal(len(self.blockchain.blockchain))
						print(f"[PROPOSAL] Created a block proposal: {proposal}")
						#time.sleep(1) Adding a sleep setting here allows for mutliple transactions. 
						self.blockchain.consensus = True


			elif data["type"] == "values":

				index = data["payload"]

				# They are requesting next block. 
				if index == self.blockchain.blockchain[-1]["index"]+1:

					# If we are not in consensus, create a block proposal and add it to the current proposals.
					if not self.blockchain.consensus:
						proposal = self.blockchain.create_proposal(index)
						print(f"[BLOCK] Received a block request from node: {self.client_address[0]} : {index}")
						
						# We are now in consensus. 
						self.blockchain.consensus = True
					

					# Send back list of proposals. This is the recieved proposals and the proposal we created (curr_proposal)
					send_prefixed(self.request,json.dumps(self.blockchain.proposals).encode())
				
				elif index < len((self.blockchain.blockchain)):
					send_prefixed(self.request,json.dumps([self.blockchain.blockchain[index]]).encode())



# Function to launch the TCP host.
def run_TCP(HOST,port,blockchain):
	with MyTCPServer((HOST, port), MyTCPHandler,blockchain) as server:
		server.serve_forever()
		

# connects to a target node and runs protocol.
def connect_to_target(server_port_pair,blockchain):
	connected = False
	while not connected:
		try: 
			s_send = socket.socket(socket.AF_INET,socket.SOCK_STREAM,)
			s_send.connect((server_port_pair[0],server_port_pair[1]))
			s_send.setblocking(True)


			connected = True
			blockchain.connected_outgoing_nodes+=1

		except Exception as e:
			pass

	print(f"Connected: {server_port_pair}")


	completed_rounds = 0
	

	while True:

		# If we are not in consensus then we have no timeout. 
		if not blockchain.consensus:
			if s_send:
				s_send.settimeout(None)		
			completed_rounds = 0

		# Consensus has begun. 
		if blockchain.consensus and connected and blockchain.rounds_total>completed_rounds:
			s_send.settimeout(5)
			print(f"ROUND {completed_rounds}")

			try:
			# Send block request. 
				send_prefixed(s_send,json.dumps({"type":"values","payload":len(blockchain.blockchain)}).encode())

			except Exception as e:
				print(e) 
				connected = False

			data = []
			# Timeout
			try: 
				data = recv_prefixed(s_send).decode()
				data = json.loads(data)

			except Exception:
				print(f"Failed to get data from target node {server_port_pair[1]}")
				connected = False
				# timeout occured. 

			# Attempt to reconnect. 
			if not connected:
				try: 
					s_send = socket.socket(socket.AF_INET,socket.SOCK_STREAM,)
					s_send.connect((server_port_pair[0],server_port_pair[1]))
					# The target port will correspond with the socket that attaches to it.
					connected = True
					print("Successful reconnection")
					continue # Go again and attempt to get the data.
				except Exception:
					print(f"Node failed completely {server_port_pair}")

					# Node has fully DC. We require another round from other nodes. 
					blockchain.finished_nodes = 0					
					blockchain.rounds_total+=1
					blockchain.connected_outgoing_nodes -= 1




			# Add new proposals to our proposal list.
			for block in data:

				if block not in blockchain.proposals and block.get("transactions") and len(block["transactions"]):
					blockchain.proposals.append(block)

			# We have completed a round. 
			completed_rounds+=1


			if blockchain.rounds_total == completed_rounds:
				blockchain.finished_nodes+=1

		
			



# Creates threads and connects to each server/port pair given. 
def establish_connections(server_port_pairs,blockchain):
    # May need to make an object to connect the nodes altogether. 

    for i in range(0,len(server_port_pairs)):
		
        new_connection_thread = threading.Thread(target = connect_to_target, args = (server_port_pairs[i], blockchain))
        new_connection_thread.start()
	

def pipeline_thread(blockchain):
		while True:


			if len(blockchain.proposals) > 0 and blockchain.finished_nodes == blockchain.connected_outgoing_nodes:
				# Find the most optimal node to append. 
				selected_block = None
				for block in blockchain.proposals:

					if not selected_block:
						selected_block = block
					else:
						if blockchain.calculate_hash(selected_block) > blockchain.calculate_hash(block):
							selected_block = block
				

				hash = blockchain.calculate_hash(selected_block)
				print(f"[CONSENSUS] Appended to the blockchain: {hash}")
				blockchain.blockchain.append(selected_block)


				# Reset everything.
				blockchain.consensus = False
				blockchain.proposals = []
				blockchain.finished_nodes = 0
				blockchain.rounds_total = 1
