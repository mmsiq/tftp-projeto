#!/usr/bin/env python3
import argparse
from tftp import *

def main():
    INET4Address = (args.host, args.port)

    while True:
        try:
            print ("Available commands are get/g, put/p, quit/q.")
            user_input = input("TFTP> ").strip().split()
            if not user_input:
                continue

            cmd = user_input[0].lower()
            if cmd in ['quit', 'q']:
                print("Exiting TFTP client.")
                break

            if len(user_input) < 2:
                print("Error: Missing filename. Usage: get <filename> or put <filename>")
                continue

            filename = user_input[1]

            if cmd in ['get', 'g']:
                get_file(INET4Address, filename)
                print(f"File '{filename}' downloaded successfully.")

            elif cmd in ['put', 'p']:
                put_file(INET4Address, filename)
                print(f"File '{filename}' uploaded successfully.")

            else:
                print(f"Error: Unknown command '{cmd}'. Available commands: get, put, quit")

        except Err as e:
            print(f"TFTP Error: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

    print('Leaving.')
#:

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='TFTP cliente')
    parser.add_argument('host', help='the host to connect to')
    parser.add_argument('-p', '--port', default=69, type=int, help='use specific port')
    args = parser.parse_args()
    main()
