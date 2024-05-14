import socketserver
from threading import Lock
import json

from network import recv_prefixed, send_prefixed
import threading
import socket
import time
from blockchain import *


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
				print(f"[NET] Received a transaction from node {self.client_address[0]} {data['message']}")

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
						#self.blockchain.consensus = True


			elif data["type"] == "values":

				index = data["payload"]

				if index == self.blockchain.blockchain[-1]["index"]+1:

					# If we are not in consensus, create a block proposal and add it to the current proposals.
					if not self.blockchain.consensus:
						proposal = self.blockchain.create_proposal(index)
						print(f"[BLOCK] Received a block request from node: {self.client_address[0]} : {data['payload']}")
						
						#self.blockchain.consensus = True
					
					# Send back list of proposals. This is the recieved proposals and the proposal we created (curr_proposal)



					send_prefixed(self.request,json.dumps(self.blockchain.rec_proposals+self.blockchain.curr_proposal).encode())



			
			# print("Received from {}:".format(self.client_address[0]))
			# print(data)
			# with self.server.blockchain_lock:
			# 	added = self.server.blockchain.add_transaction(data)
			# send_prefixed(self.request, json.dumps({'response': added}).encode())




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
            # The target port will correspond with the socket that attaches to it.
			connected = True
		except Exception as e:
			time.sleep(1)
	
	print(f"Connected: {server_port_pair}")

	while True:
		# Consensus has begun. 
		if blockchain.consensus:
			s_send.timeout(5)

			try:
			# Send block request. 
				send_prefixed(s_send,json.dumps({"type":"values","payload":len(blockchain.blockchain)}).encode())

			except: 
				connected = False

			# Timeout
			try: 
				data = recv_prefixed(s_send).decode()
			except Exception:
				connected = False
				# timeout occured. 


			if not connected:
				try: 
					s_send = socket.socket(socket.AF_INET,socket.SOCK_STREAM,)
					s_send.connect((server_port_pair[0],server_port_pair[1]))
					# The target port will correspond with the socket that attaches to it.
					connected = True
				except Exception as e:
					print(f"Node failed completely {server_port_pair}")

			


			# Wait for return.
			


# Creates threads and connects to each server/port pair given. 
def establish_connections(server_port_pairs,blockchain):
    # May need to make an object to connect the nodes altogether. 

    for i in range(0,len(server_port_pairs)):
		
        new_connection_thread = threading.Thread(target = connect_to_target, args = (server_port_pairs[i], blockchain))
        new_connection_thread.start()
	
