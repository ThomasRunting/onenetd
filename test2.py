#!/usr/bin/env python
import socket, threading

host = "127.0.0.1"
port = 4000
many = 20
total = 10000
total_lock = threading.Lock()

class Hammer(threading.Thread):
	def run(self):
		global host, port, total, total_lock
		while 1:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))
			f = s.makefile("w+")
			try: 
				r = f.readline()
			except IOError:
				r = "<IO error>"
			s.close()	
			total_lock.acquire()
			total -= 1
			n = total
			total_lock.release()
			print n, "got back response:", r
			if n < 1: break

threads = []
for i in range(many):
	h = Hammer()
	threads.append(h)
	h.start()

for t in threads: t.join()

