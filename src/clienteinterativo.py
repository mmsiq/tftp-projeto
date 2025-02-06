from tftp import *
from socket import gethostname, gethostbyname
import os

def main():
    try:
        flag = True
        buffer = []

        host_name = gethostname()
        addr = (gethostbyname(host_name), host_name)

        (host, port) = input('Enter host:port --> ').split(':')
        INET4Address = host,port   
        if INET4Address:
            buffer.append('Connecting from host: {0} to host: {1}:{2}, mode: {3}'.format(addr, INET4Address, 'octet'))

            for p in range(len(buffer)):
                print(buffer.pop())
        else:
            flag = False
            print("Could not create TFTPClient() with: {0}:{1}".format(INET4Address))
        
        while flag:

            method = input('\nEnter get/g, put/p, quit/q --> ').lower()

            if method in ['quit', 'q']:
                buffer.append("Flag off")
                flag = False
                
            else:
                remote_file, local_file = input('Enter remote filename --> '), input('Enter local filename --> ')
            
                if method in ['get', 'g']:
                    if not remote_file:
                        raise Exception("Remote file is invalid!");
                    else:
                        if not local_file:
                            local_file = remote_file
                        if get_file(remote_file, local_file):
                            if '.' in os.path.splitext(local_file)[-1]:
                                if os.path.isfile(local_file):
                                    buffer.append("Successfully read file {0} from server {1}:{2} to path {3}/{4}".format(remote_file, INET4Address, os.getcwd(), local_file))
                    
                elif method in ['put', 'p']:
                    
                    if not os.path.isfile(local_file):
                        raise Exception("File %s does not exist!" % local_file)
                    else:
                        if not remote_file:
                            remote_file = local_file
                        if put_file(local_file, remote_file):
                            buffer.append("Successfully wrote file {0} from path {1} to server {2}:{3}/{4}".format(local_file, os.getcwd(), host, port, remote_file))
                        

            for i in range(len(buffer)):
                print(buffer.pop())
            
    except Exception as err:
        print("main.err: %s" % err)
        
    finally:
        print("Leaving. . .")


if __name__ == '__main__':
    main()
