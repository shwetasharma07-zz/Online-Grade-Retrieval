#!/usr/bin/env python3

#########################################################################

import socket
import argparse
import sys
import csv
import getpass
import hashlib

#########################################################################
# Server Class
#########################################################################

class Server:

	HOSTNAME = socket.gethostname()
	PORT = 50000

	RECV_SIZE = 1024
	BACKLOG = 10

	MSG_ENCODING = "utf-8"

	def __init__(self):
		self.process_csv_file()
		self.create_listen_socket()
		self.process_connections_forever()

	def process_csv_file(self):
		try:
			with open('course_grades_v01.csv') as csvfile:
				readCSV = csv.reader(csvfile, delimiter=',')
				#print(readCSV)

				self.idNum = []
				self.password = []
				self.lastName = []
				self.firstName = []
				self.midterm = []
				self.lab1 = []
				self.lab2 = []
				self.lab3 = []
				self.lab4 = []

				for row in readCSV:
					print(row)
					'''idNum = row[0]
					password = row[1]
					lastName = row[2]
					firstName = row[3]
					midterm = row[4]
					lab1 = row[5]
					lab2 = row[6]
					lab3 = row[7]
					lab4 = row[8]'''

					self.idNum.append(row[0])
					self.password.append(row[1])
					self.lastName.append(row[2])
					self.firstName.append(row[3])
					self.midterm.append(row[4])
					self.lab1.append(row[5])
					self.lab2.append(row[6])
					self.lab3.append(row[7])
					self.lab4.append(row[8])


		except Exception as msg:
			print(msg)
			sys.exit(1)

	def create_listen_socket(self):
		try:
			# Create the IPv4 TCP socket
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			# Socket layer options. Set to be immediately reused
			self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

			# Bind socket to socket address (IP address & port)
			self.socket.bind((Server.HOSTNAME, Server.PORT))

			# Set socket to listen
			self.socket.listen(Server.BACKLOG)
			print("Listening on port {}...".format(Server.PORT))

		except Exception as msg:
			print(msg)
			sys.exit(1)

	def process_connections_forever(self):
		try:
			while True:
				# Block while waiting for incoming connections. When
				# one is accepted, pass new socket reference to 
				# connection handler.
				# Parameter returns conn and address tuple
				# conn is new socket object and address is port
				print("1st")
				self.connection_handler(self.socket.accept())
				print("2nd")
		except Exception as msg:
			print(msg)
		except KeyboardInterrupt:
			print()
		finally:
			self.socket.close()
			sys.exit(1)

	def connection_handler(self, client):
		connection, address_port = client
		address, ip = address_port
		print("*" * 72)
		print("Connection received from {} on port {}.".format(address,ip))

		while True:
			try:
				# Receive bytes over TCP connection. Will block till 
				# 1 byte or more is available.
				self.recvd_bytes = connection.recv(Server.RECV_SIZE)

				# Decode received bytes and output them in string
				self.recvd_str = self.recvd_bytes.decode(Server.MSG_ENCODING)
				self.recvd_str = str(self.recvd_bytes)
				print("Received ID/password ", self.recvd_str, " from client.")
				self.check_user()

			except KeyboardInterrupt:
				print()
				print("Closing client connection....")
				connection.close()
				break

	def check_user(self):
		try:
			for row in range(1,len(self.idNum)):
				#checkPass = self.idNum[row] + self.password[row]
				checkHash = hashlib.sha256(self.idNum[row].encode("utf-8") + self.password[row].encode("utf-8")).hexdigest()
				checkHash = str(checkHash).encode(Server.MSG_ENCODING)
				#checkHash_str = checkHash.decode(Server.MSG_ENCODING)
				#checkHash = str(checkHash)
				print(checkHash)
				if(checkHash == self.recvd_bytes):
					self.index = row
					print("Found match!")
					self.get_user_info()
					break
				else:
					continue
			sys.exit(1)
		except KeyboardInterrupt:
				print()
				print("Closing client connection....")
				connection.close()

				#1788788,SiKoLkVb

	def get_user_info(self):
		print("Here are your marks:")
		print(self.lastName[self.index])
		print(self.firstName[self.index])
		print(self.midterm[self.index])
		print(self.lab1[self.index])
		print(self.lab2[self.index])
		print(self.lab3[self.index])
		print(self.lab4[self.index])
		self.process_connections_forever()

#########################################################################
# Client Class
#########################################################################

class Client:

	SERVER_HOSTNAME = socket.gethostname()
	RECV_SIZE = 1024

	MSG_ENCODING = "utf-8"

	def __init__(self):
		self.get_socket()
		self.connect_to_server()
		self.send_input_to_server()

	def get_socket(self):
		try:
			# Create IPv4 TCP socket
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		except Exception as msg:
			print(msg)
			sys.exit(1)

	def prompt_credentials(self):
		try:

			userID = input("Enter your username: ")
			password = getpass.getpass(prompt='Enter your password: ')

			sha256_object = hashlib.sha256(userID.encode("utf-8")+password.encode("utf-8")).hexdigest()
			return sha256_object

		except Exception as msg:
			print(msg)
			sys.exit(1)

	def connect_to_server(self):
		try:
			# Connect to server using its socket address tuple
			self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))

		except Exception as msg:
			print(msg)
			sys.exit(1)

	def send_input_to_server(self):
		while True:
			try:
				self.sent_hash = self.prompt_credentials()
				self.sent_hash = str(self.sent_hash).encode(Client.MSG_ENCODING)
				self.connection_send()
			except (KeyboardInterrupt, EOFError):
				print()
				print("Closing server connection....")
				self.socket.close()
				sys.exit(1)

	def connection_send(self):
		try:
			# Send string objects over the connection. String has 
			# already been utf-8 encoded.
			self.socket.sendall(self.sent_hash)
			print("ID/password hash ", self.sent_hash, " sent to server.")
		except Exception as msg:
			print(msg)
			sys.exit(1)

#########################################################################
# Command line arguements
#########################################################################

if __name__ == '__main__':
	roles = {'server': Server, 'client': Client}
	parser = argparse.ArgumentParser(description = 'What does this do?')

	parser.add_argument('-r', '--role', choices=roles,
						help='server or client role', 
						required=True, type=str)

	args = parser.parse_args()
	roles[args.role]()

#########################################################################


	
