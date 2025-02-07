#!/usr/bin/env python3
import argparse
from socket import gethostbyname
from tftp import *

def main():
    try:
        host = gethostbyname(args.host)
        port = args.port
        cmd = args.command.lower()
        filename = args.file_name

        INET4Address = (host, port)

        if cmd in ['get', 'g']:
            get_file(INET4Address, filename)
            print(f"File '{filename}' downloaded successfully.")

        elif cmd in ['put', 'p']:
            put_file(INET4Address, filename)
            print(f"File '{filename}' uploaded successfully.")

        else:
            print(f"Error: Unknown command '{cmd}'. Valid commands: get, put")

    except Err as e:
        print(f"TFTP Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        print('Leaving.')

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='TFTP client')
	parser.add_argument('host', help='the host (IP or server name) to connect to')
	parser.add_argument('command', help='enter command: get, put, or quit')
	parser.add_argument('file_name', help='name of the file to read/write')
	parser.add_argument('-p', '--port', default=69, type=int, help='use specific port')
	args = parser.parse_args()
	main()