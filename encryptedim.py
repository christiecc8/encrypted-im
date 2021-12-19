# Christie Cheong
# HW 1 Part 2

import argparse
import select
import socket
import sys
import signal
from struct import *
from base64 import b64encode, b64decode
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

# define some globals
HOST = ''
PORT = 9999
SOCKET_LIST = []

def handler(signum,frame):
    """ handle a SIGINT (ctrl-C) keypress """
    for s in SOCKET_LIST:                 #close all sockets
        s.close()
    sys.exit(0)

def wait_for_incoming_connection():
    """
    create a server socket and wait for incoming connection

    returns the server socket
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    SOCKET_LIST.append(s)
    SOCKET_LIST.append(conn)
    return conn
    
def connect_to_host( dst ):
    """ connects to the host 'dst' """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect( (dst,PORT) )
        SOCKET_LIST.append(s)
        return s
    except socket.error:
        print( "Could not connect to %s." % dst )
        sys.exit(0)

# Parameters: IV, config key, message
# Used for encrypting the message
# reference: https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
def enc (iv, ckey, message, cipher):
    to_bytes = message.encode('utf-8')
    padded = pad(to_bytes, 16)
    ciphertext = cipher.encrypt(padded)
    return ciphertext

# Parameters: IV, config key, message
# Used for encrypting message length
# reference: https://docs.python.org/3.8/library/struct.html
# reference: https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
def enc_len (iv, ckey, message, cipher):
    to_bytes = pack("l", len(message))
    padded = pad(to_bytes, 16)
    ciphertext_len = cipher.encrypt(padded)
    return ciphertext_len

# Parameters: authenticity key, message 
# reference: https://pycryptodome.readthedocs.io/en/latest/src/hash/hmac.html
def gen_hmac(akey, message):
    h = HMAC.new(akey, msg=message, digestmod=SHA256)
    h.update(message)
    return h.digest();
    
# Parameters: authenticity key, HMAC object, message 
# reference: https://pycryptodome.readthedocs.io/en/latest/src/hash/hmac.html
def verify_hmac(akey, mac, message):
    h = HMAC.new(akey, msg=message, digestmod=SHA256)
    h.update(message)
    try:
        h.verify(mac)
        return 0
    except ValueError:
        sys.stdout.write("ERROR: HMAC verification failed")
        return 1

# Parameters: IV, config key, message
# Used for decrypting integer
# reference: https://docs.python.org/3.8/library/struct.html
# reference: https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
def dec_len (iv, ckey, message, cipher):
    plaintext_len = unpack("l", unpad(cipher.decrypt(message), 16))[0]
    return plaintext_len

# Parameters: IV, config key, message
# Used for decrypting message
# reference: https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
def dec (iv, ckey, message, cipher):
    plaintext = unpad(cipher.decrypt(message), 16).decode('utf-8')
    return plaintext

def parse_command_line():
    """ parse the command-line """
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--c", dest="dst", help="destination address")
    parser.add_argument("-s", "--s", dest="server", action="store_true",
                    default=False, help="start server mode")
    parser.add_argument('--confkey', dest="ckey")
    parser.add_argument('--authkey', dest="akey")

    options = parser.parse_args()
 
    if not options.dst and not options.server:
        parser.print_help()
        parser.error("must specify either server or client mode")

    return options


if __name__ == "__main__":

    options = parse_command_line()

    # catch when the user presses CTRL-C
    signal.signal(signal.SIGINT,handler)

    if options.server:
        s = wait_for_incoming_connection()
    elif options.dst:
        s = connect_to_host(options.dst)
    else:
        assert(False)                         # this shouldn't happen


    rlist = [ s, sys.stdin ]
    wlist = []
    xlist = []
    
    # reference: https://pycryptodome.readthedocs.io/en/latest/src/hash/sha256.html
    confkey = SHA256.new()
    confkey.update(options.ckey.encode('utf-8'))
    authkey = SHA256.new()
    authkey.update(options.akey.encode('utf-8'))
    
    while True:
        (r, w, x) = select.select(rlist,wlist,xlist)
        if s in r:                            # there is data to read from network
            
            
            # Receive IV in the clear
            # reference: https://pycryptodome.readthedocs.io/en/latest/src/random/random.html
            iv = s.recv(16)
            
            # Generate cipher object
            cipher = AES.new(confkey.digest(), AES.MODE_CBC, iv)
            
            # Receive encrypted message length and decrypt
            cipher_len = s.recv(16)
            decrypted_message_len = dec_len(iv, confkey.digest(), cipher_len, cipher)
            
            # Receive first MAC and verify
            mac1 = s.recv(32)
            if (verify_hmac(authkey.digest(), mac1, iv + cipher_len) == 1):
                sys.exit(0)
            
            # Receive encrypted message and decrypt
            length = decrypted_message_len + (16 - (decrypted_message_len % 16))
            ciphertext = s.recv(length)
            decrypted = dec(iv, confkey.digest(), ciphertext, cipher)
            
            # Receive second MAC and verify
            mac2 = s.recv(32)
            if (verify_hmac(authkey.digest(), mac2, ciphertext) == 1):
                sys.exit(0)
            
            # Print decrypted message
            sys.stdout.write(decrypted)
            sys.stdout.flush()
            
        if sys.stdin in r:                    # there is data to read from stdin
            data = sys.stdin.readline()
            if data == "":                    # we closed STDIN
                break
            
            # Generate cipher object and extract IV
            cipher = AES.new(confkey.digest(), AES.MODE_CBC)
            iv = cipher.iv
            
            # Generate and send IV in the clear
            s.send(iv)
            
            # Encrypt message length and send
            cipher_len = enc_len(iv, confkey.digest(), data, cipher)
            s.send(cipher_len)
            
            # HMAC message length using authenticity key and send
            mac1 = gen_hmac(authkey.digest(), iv + cipher_len)
            s.send(mac1)
            
            # Encrypt message then send
            ciphertext = enc(iv, confkey.digest(), data, cipher)
            s.send(ciphertext)
            
            # HMAC encrypted message then send
            mac2 = gen_hmac(authkey.digest(), ciphertext)
            s.send(mac2)
        

    """
            If we get here, then we've got an EOF in either stdin or our network.
            In either case, we iterate through our open sockets and close them.
    """
    for sock in SOCKET_LIST:
        sock.close()

    sys.exit(0)                           # all's well that ends well!
