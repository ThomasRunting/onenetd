#!/usr/bin/env python
import socket

host = "localhost"
port = 4000
many = 500

conns = []

def make_connection():
	global conns, host, port
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host, port))
	conns.append(s)

def kill_connection():
	global conns
	(s, conns) = conns[0], conns[1:]
	s.close()

print "Making conns..."
for i in range(many):
	print i
	make_connection()

raw_input("Hit return")

for i in range(many):
	kill_connection()

