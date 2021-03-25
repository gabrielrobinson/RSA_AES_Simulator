# Author: Gabriel Robinson
# Date:   April 15, 2019
# Course: CS 4480, University of Utah, School of Computing
# Copyright: CS 4480 and Gabriel Robinson - This work may not be copied for use in Academic Coursework.
#
# I, Gabriel Robinson, certify that I wrote this code from scratch and did not copy it in part or whole from
# another source.  Any references used in the completion of the assignment are cited in my written work.
#
# File Contents:
#
#   james.py makes a request to bruce.py. bruce.py will respond with a digest containing his name, his public
#   key, and the public key signed with the certificate agencies private key. It is the job of james.py to
#   validate the integrity of this file. It verifies that the name is bruce, verifies the signature. Once
#   this is completed, james.py sends a digest containing the message encrypted with a  symmetric key generated
#   on the fly, the symmetric key encrypted with bruces public key, and a hash of the encrypted message, so that
#   the integrity of the message can be verified once bruce receives it. All encryption and decryption schemes
#   are provided by the cryptography module.

import sys
import os
import socket
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


# loads public key from specified file
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
def load_public_key(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend())
        return public_key


# parses response from data
# returns the name of the sender, their public key, and their signature
def parse_response(data):
    data = data[1:]
    data = data[:-2]
    sig_fields = data.split(b', ')
    if len(sig_fields) != 3:
        print('incorrect number of fields in signature')
        exit(0)
    name = sig_fields[0].split(b':')[1]
    bobs_pub_key = sig_fields[1].split(b':')[1]
    signature = sig_fields[2].split(b':')[1]
    signature = base64.b64decode(signature)
    return name, bobs_pub_key, signature


# takes a socket as a parameter and returns the byte string
# received from that socket
def get_response(sock):
    buffer = b''
    while True:
        data = sock.recv(1024)
        buffer += data
        if b'\00' in data:
            break
    return data


# creates sha 256 hash of the provided key.
def sha_256_hash(encrypted_symmetric_key):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(encrypted_symmetric_key)
    hash_bytes = digest.finalize()
    return hash_bytes


# given a symmetric key and iv, the following function
# encrypts the given message with the symmetric key
def symmetric_encrypt(message, symmetric_key, iv):
    remainder = len(message) % len(symmetric_key)
    if remainder != 0:
        length_padding = len(symmetric_key) - remainder
        for i in range(0, length_padding):
            message += b' '
    backend = default_backend()
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=backend)
    encrypt_object = cipher.encryptor()
    encrypted_message = encrypt_object.update(message) + encrypt_object.finalize()
    return encrypted_message


# takes a key and a bytes object and returns the bytes object encrypted
# by the key.
def asymmetric_encrypt(key, plaintext):
    cipher = key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))
    return cipher


# generates message from to send to bob based upon
# the flag. the flag can either be '-message' or
# it can be '-file'. Otherwise it prints that an
# error has made and exits.
def generate_message(arguments, flag, key_bytes):

    # check to see if a message or a file is being sent
    message = b''
    if flag == '-message':
        message += bytes(arguments[6], 'utf-8')
    elif flag == '-file':
        # if file then try and read from the file system
        filename = arguments[6]
        try:
            file = open(filename, 'rb')
            message += file.read()
        except IOError:
            print('{} is an invalid filename'.format(filename))
            exit(0)
    else:
        print('unknown option used')
        exit(0)

    # start by generating the symmetric key
    symmetric_key = os.urandom(32)
    print('Symmetric key:\n   {}\n'.format(symmetric_key))
    iv = os.urandom(16)
    print('IV:\n   {}\n'.format(symmetric_key))
    # encrypt message with the symmetric key
    print("Generating encrypted message...\n")
    encrypted_message = symmetric_encrypt(message, symmetric_key, iv)
    print('AES-Encrypted Message:\n   {}\n'.format(encrypted_message))
    message_hash = sha_256_hash(encrypted_message)
    print('SHA256 Hash of AES-Encrypted Message:\n   {}\n'.format(message_hash))
    # take the bytes of bobs public key and create key object from those bytes
    pub_key = serialization.load_pem_public_key(key_bytes, backend=default_backend())
    # encrypt the symmetric key with bob's public key
    encrypted_symmetric_key = asymmetric_encrypt(pub_key, symmetric_key + iv)
    print('RSA encrypted Symmetric Key and IV:\n   {}\n'.format(encrypted_symmetric_key))


    response = b''
    if flag == '-message':
        # create message to send to bob
        # For a simple message, the following JSON will be sent:
        response += b'{' + \
                    b'\'message\': \'' + base64.b64encode(encrypted_message) + b'\', ' + \
                    b'\'verify\': \'' + base64.b64encode(message_hash) + b'\', ' + \
                    b'\'key\': \'' + base64.b64encode(encrypted_symmetric_key) + \
                    b'\'}\0'

    elif flag == '-file':
        # For a file, the following JSON will be sent:
        encrypted_filename = symmetric_encrypt(filename.encode('utf-8'), symmetric_key, iv)
        response += b'{\'file_name\': \'' + base64.b64encode(encrypted_filename) + b'\', ' + \
                    b'\'contents\': \'' + base64.b64encode(encrypted_message) + b'\', ' + \
                    b'\'verify\': \'' + base64.b64encode(message_hash) + b'\', ' + \
                    b'\'key\': \'' + base64.b64encode(encrypted_symmetric_key) + \
                    b'\'}\0'
    return response


def main():
    # check and make sure that the correct number of variables was
    # provided
    if len(sys.argv) != 7:
        print('incorrect number of program arguments')
        exit(0)
    print('--------------------------------------\n')
    # get environment variables
    ip = sys.argv[1]
    port = int(sys.argv[3])
    ca_pub_filename = sys.argv[4]
    flag = sys.argv[5]
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Connect the socket to the port where the server is listening
    sock.connect((ip, port))
    print('James has connected wth with {}:{}\n'.format(ip, str(port)))
    try:
        # Send data
        sock.sendall(b'\0')
        # Get response
        data = get_response(sock)
        data = data[:-1]
        print('Received:\n  {}\n'.format(data))
        # Parse response
        name, bruces_pub_key_bytes, signature = parse_response(data)
        # load the certificate authorities public key
        certificate_authority_pubkey = load_public_key(ca_pub_filename)
        # verify signature with the message
        print('Verifying CA signature...\n')
        certificate_authority_pubkey.verify(signature,
                                            bruces_pub_key_bytes,
                                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                        salt_length=padding.PSS.MAX_LENGTH),
                                            hashes.SHA256())
        # confirm name = bob
        if name != b'Batman':
            print('Incorrect signature... Exiting...\n')
            exit(0)
        else:
            print('Batman identified as endpoint through signature verification...\n')

        response = generate_message(arguments=sys.argv, flag=flag, key_bytes=bruces_pub_key_bytes)
        sock.sendall(response)
        # print('Sending:\n  {}\n'.format(response))
        print('Sending datagram including AES-Encrypted Message, SHA256 Hash of AES-Encrypted Message, and RSA encrypted Symmetric Key and IV...')
    finally:
        print('--------------------------------------\n\n')
        print('closing socket')
        sock.close()


if __name__ == "__main__":
    main()
