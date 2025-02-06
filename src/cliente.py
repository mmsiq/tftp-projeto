#!/usr/bin/env python3
import argparse
from socket import gethostname, gethostbyname
from tftp import *
import os

def main():
	try:
		args, buffer, addr = parser.parse_args(), [], (gethostbyname(gethostname()), gethostname()), 

		(host, port, cmd, filename) = args.host, args.port, args.command.lower(), args.file_name
		INET4Address = host,port  
		if cmd in ['get','g']:
			get_file((INET4Address), filename)
			print(f"File '{filename}' sent successfully.")

		elif cmd in ['put', 'p']:
			put_file(INET4Address, filename)
			print(f"File '{filename}' sent successfully.")


	except Err as e:
		print(f"TFTP Error: {e}")
	except Exception as e:
		print(f"An error occurred: {e}")


	except Exception as err:
		print('main.err: %s' % err)

	finally:
		print('Leaving.')
#:

if __name__ == '__main__':	
	parser = argparse.ArgumentParser(description='TFTP cliente')
	parser.add_argument('host', help='the host to connect to')
	parser.add_argument('command', help='enter command: read, write or quit')
	parser.add_argument('file_name', help='name of the file to read/write')
	parser.add_argument('-p', '--port', default=69, help='use specific port')
	main()
      