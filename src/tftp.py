import ipaddress
import re
import socket
from socket import socket, AF_INET, SOCK_DGRAM
import string
import struct

MAX_DATA_LEN = 512          #bytes
DEFAULT_MODE = 'octet'      #transfer mode (one of 'octet', 'netascii', etc.)
INACTIVITY_TIMEOUT = 25.0   #segs
DEFAULT_BUFFER_SIZE = 8192  #byes

# TFTP message opcodes
RRQ = 1                     # Read ReQuest
WRQ = 2                     # Write ReQuest
DAT = 3                     # Data transfer
ACK = 4                     #acknowledge
ERR = 5                     #. Error packet; what the server responds if a read/write 
                            # can't be processed, read and write errors during file. 
                            # transmission also cause this message to be sent, and  
                            # transmission is then terminated. The error number gives a 
                            # numeric error code, followed by an ASCII error message that 
                            # might contain additional, operating system specific 
                            # information.

ERR_NOT_DEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
# TODO: Acrescentar códigos de erro em falta

ERROR_MESSAGES = {
    ERR_NOT_DEFINED: 'Not defined, see error message (if any).',
    ERR_FILE_NOT_FOUND: 'File not found.',
    ERR_ACCESS_VIOLATION: 'Access violation.',
    # TODO: Acrescentar mensagens de erro em falta
}


INET4Address = tuple[str, int]
# Send and receive files

def get_file(server_addr: INET4Address, filename: str):
    """
    Get the remote file given by `filename` through a TFTP RRQ
    connection to remote server at `server_addr`.
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.settimeout(INACTIVITY_TIMEOUT)
        with open(filename, 'wb') as out_file:
            rrq = pack_rrq(filename)
            next_block_number = 1
            sock.sendto(rrq, server_addr)

            while True:
                packet, server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                opcode = unpack_opcode(packet)

                if opcode == DAT:
                    block_number, data = unpack_dat(packet)
                    if block_number not in (next_block_number, next_block_number - 1):
                        error_msg = f'Invalid block number: {block_number}'
                        raise ProtocolError(error_msg)

                    if block_number == next_block_number:
                        out_file.write(data)
                        next_block_number += 1
                    
                    ack = pack_ack(block_number)
                    sock.sendto(ack, server_addr)

                    if len(data) < MAX_DATA_LEN:
                        return

                elif opcode == ERR:
                    error_code, error_msg = unpack_err(packet)
                    raise Err(error_code, error_msg)
                
                else:
                    error_msg = f'Invalid packet opcode: {opcode}. Expecting {DAT=}'
                    raise ProtocolError(error_msg)
#:              
def put_file(server_addr: INET4Address, filename: str):
    """
    Send the local file given by `filename` to the remote server at `server_addr`
    through a TFTP WRQ connection.
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.settimeout(INACTIVITY_TIMEOUT)
        with open(filename, 'rb') as in_file:
            wrq = pack_wrq(filename)
            block_number = 1
            sock.sendto(wrq, server_addr)

            
            while True:
                packet, server_addr = sock.recvfrom(DEFAULT_BUFFER_SIZE)
                opcode = unpack_opcode(packet)

                if opcode == ACK:
                    ack_block_number = unpack_ack(packet)
                    if ack_block_number != block_number -1 and ack_block_number != block_number:
                        raise ProtocolError(f"Incorrect block number in ACK: {ack_block_number}, expecting {block_number -1} or {block_number}")
                    if ack_block_number == block_number -1:
                        continue

                    data = in_file.read(MAX_DATA_LEN)
                    if not data: 
                        return

                    dat = pack_dat(block_number, data)
                    sock.sendto(dat, server_addr)
                    block_number += 1


                elif opcode == ERR:
                    error_code, error_msg = unpack_err(packet)
                    raise Err(error_code, error_msg)

                else:
                    raise ProtocolError(f"Invalid opcode: {opcode}, expecting ACK or ERR")
#:              


# Packet packing and unpacking
def pack_rrq(filename: str, mode = DEFAULT_MODE) -> bytes:
    return _pack_rq(RRQ, filename, mode)
#:

def pack_wrq(filename: str, mode = DEFAULT_MODE) -> bytes:
    return _pack_rq(WRQ, filename, mode)
#:

def _pack_rq(opcode: int, filename: str, mode = DEFAULT_MODE) -> bytes:
    if not is_ascii_printable(filename):
        raise TFTPValueError(f'Invalid filename: {filename}. Not ASCII printable')
    filename_bytes = filename.encode() + b'\x00'
    mode_bytes = mode.encode() + b'\x00'
    rrq_fmt = f'!H{len(filename_bytes)}s{len(mode_bytes)}s'
    return struct.pack(rrq_fmt, opcode, filename_bytes, mode_bytes)
#:

def unpack_rrq(packet: bytes) -> tuple[str, str]:
    return _unpack_rq(RRQ, packet)
#:


def unpack_wrq(packet: bytes) -> tuple[str, str]:
    return _unpack_rq(WRQ, packet)
#:

def _unpack_rq(expected_opcode: int, packet: bytes) -> tuple[str, str]:
    received_opcode = unpack_opcode (packet)
    if received_opcode != expected_opcode:
        raise TFTPValueError(f'Invalid opcode: {received_opcode}. Expected {expected_opcode}') 
    delim_pos = packet.index(b'\x00', 2)
    filename = packet [2:delim_pos].decode()
    mode = packet [delim_pos + 1:-1].decode() 
    return filename, mode
#:

def unpack_opcode (packet: bytes) -> int:
    opcode,  *_ = struct.unpack('!H', packet[:2])
    if opcode not in (RRQ, WRQ, DAT, ACK, ERR):
        raise TFTPValueError(f'Invalid opcode: {opcode}') 
    return opcode
#:

def pack_dat(block_number: int, data: bytes) -> bytes:
    if len(data) > MAX_DATA_LEN:
        raise TFTPValueError(f'Data length exceeds {MAX_DATA_LEN} bytes')
    fmt = f'!HH{len(data)}s'
    return struct.pack(fmt, DAT, block_number, data)
#:

def unpack_dat(packet: bytes) -> tuple[int, bytes]:
    opcode, block_number = struct.unpack('!HH', packet[:4])
    if opcode != DAT:
        raise TFTPValueError(f'Invalid opcode: {opcode}')
    return block_number, packet[4:]
#:

def pack_ack(block_number: int) -> bytes:
    return struct.pack('!HH', ACK, block_number)
#:

def unpack_ack(packet: bytes) -> int:
    if len(packet) > 4:
        raise TFTPValueError(f'Invalid packet length: {len(packet)}')
    return struct.unpack('!H', packet[2:4])[0]
#:

def pack_err(error_num: int, error_msg: str) -> bytes:
    if not is_ascii_printable(error_msg):
        raise TFTPValueError(f'Invalid error message: {error_msg}. Not ASCII printable')
    error_msg_bytes = error_msg.encode() + b'\x00'
    fmt = f'!HH{len(error_msg_bytes)}s'
    return struct.pack(fmt, ERR, error_num, error_msg_bytes)
#:

def unpack_err(packet: bytes) -> tuple[int, str]:
    opcode, error_num, error_msg = struct.unpack(f'!HH{len(packet)-4}s', packet)
    if opcode != ERR:
        raise ValueError(f'Invalid opcode: {opcode}')
    return error_num, error_msg[:-1]
#:
################################################################################
##
##      ERRORS AND EXCEPTIONS
##
################################################################################
 
class TFTPValueError(ValueError):
    pass
#:
 
class NetworkError(Exception):
    """
    Any network error, like "host not found", timeouts, etc.
    """
#:
 
class ProtocolError(NetworkError):
    """
    A protocol error like unexpected or invalid opcode, wrong block
    number, or any other invalid protocol parameter.
    """
#:
 
class Err(Exception):
    """
    An error sent by the server. It may be caused because a read/write
    can't be processed. Read and write errors during file transmission
    also cause this message to be sent, and transmission is then
    terminated. The error number gives a numeric error code, followed
    by an ASCII error message that might contain additional, operating
    system specific information.
    """
    def __init__(self, error_code: int, error_msg: str):
        super().__init__(f'TFTP Error {error_code}')
        self.error_code = error_code
        self.error_msg = error_msg
    #:
#:
 
################################################################################
##
##      COMMON UTILITIES
##      Mostly related to network tasks
##
################################################################################
 
def _make_is_valid_hostname():
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    def _is_valid_hostname(hostname):
        """
        From: http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        See also: https://en.wikipedia.org/wiki/Hostname (and the RFC
        referenced there)
        """
        if not 0 < len(hostname) <= 255:
            return False
        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]
        return all(allowed.match(x) for x in hostname.split("."))
    return _is_valid_hostname
#:
is_valid_hostname = _make_is_valid_hostname()
 
def get_host_info(server_addr: str) -> tuple[str, str]:
    """
    Returns the server ip and hostname for server_addr. This param may
    either be an IP address, in which case this function tries to query
    its hostname, or vice-versa.
    This functions raises a ValueError exception if the host name in
    server_addr is ill-formed, and raises NetworkError if we can't get
    an IP address for that host name.
    TODO: refactor code...
    """
    try:
        ipaddress.ip_address(server_addr)
    except ValueError:
        # server_addr not a valid ip address, then it might be a
        # valid hostname
        if not is_valid_hostname(server_addr):
            raise ValueError(f"Invalid hostname: {server_addr}.")
        server_name = server_addr
        try:
            # gethostbyname_ex returns the following tuple:
            # (hostname, aliaslist, ipaddrlist)
            server_ip = socket.gethostbyname_ex(server_name)[2][0]
        except socket.gaierror:
            raise NetworkError(f"Unknown server: {server_name}.")
    else:  
        # server_addr is a valid ip address, get the hostname
        # if possible
        server_ip = server_addr
        try:
            # returns a tuple like gethostbyname_ex
            server_name = socket.gethostbyaddr(server_ip)[0]
        except socket.herror:
            server_name = ''
    return server_ip, server_name
#:
 
def is_ascii_printable(txt: str) -> bool:
    return set(txt).issubset(string.printable)
    # ALTERNATIVA: return not set(txt) - set(string.printable)
#:
