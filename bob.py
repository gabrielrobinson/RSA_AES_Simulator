# Author: Gabriel Robinson
# Date:   April 15, 2019
# Course: CS 4480, University of Utah, School of Computing
# Copyright: CS 4480 and Gabriel Robinson - This work may not be copied for use in Academic Coursework.
#
# I, Gabriel Robinson, certify that I wrote this code from scratch and did not copy it in part or whole from
# another source.  Any references used in the completion of the assignment are cited in my written work.
#
#   File Contents:
#
#   bob.py opens a socket connection and waits for a request. Once a request is received it will send
#   send a message digest containing his name, his public key, and a signature of his public key signed
#   by the certificate agencies private key. bob.py then waits for a response from the requesting host.
#   This datagram should either contain a message or a file. that is encrypted with a symmetric key. This
#   symmetric key should also be in the message and should be encrypted with bob's public key. Furthermore,
#   the message should contain a signature of the encrypted message, in order to verify. This verification
#   is done with sha256 hashing function provided by the cryptography module. bob.py uses the cryptography
#   module in order to asymmetric decryption and encryption, as well as symmetric decryption.

import sys
import socket
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# loads private key from file with given filename
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
def load_private_key(filename):
    with open(filename, "rb") as key_file:
        key_bytes = key_file.read()
        private_key = serialization.load_pem_private_key(
            key_bytes, password=None, backend=default_backend())
        return private_key


# loads public key from file with given name
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
def load_public_key(filename):
    with open(filename, "rb") as key_file:
        key_bytes = key_file.read()
        public_key = serialization.load_pem_public_key(
            key_bytes, backend=default_backend())
        return public_key


# signs the message with the provided message and key
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
def sign(message, key):
    signature = key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    return signature


# generates a certificate with bob's public key,
# the the public key signed by the certificate agencies
# private key, and the name of the sender
def generate_bobs_certificate(bobs_pub, cert_priv):
    # load bob's public key
    bobs_public_key = load_public_key(bobs_pub)
    # load certificate authorities private key
    certificate_authority_private_key = load_private_key(cert_priv)
    # cast bob's public key to a byte string and then sign the public key
    bobs_public_key_bytes = bobs_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # sign bob's public key with the CA's private key
    signature = base64.b64encode(sign(bobs_public_key_bytes, certificate_authority_private_key))
    # generate certificate json object and return it
    certificate_json = b"{{name:bob, pub_key:" + bobs_public_key_bytes + b", signature:" + signature + b"}}\0"
    return certificate_json


# takes a socket as a parameter and returns the byte string
# received from that socket
def get_response(sock):
    data = b''
    while True:
        buffer = sock.recv(1024)
        data += buffer
        if b'\x00' in buffer:
            break
    return data


# takes a bytes object and returns a sha256 hash of the byte string
def sha_256_hash(byte_string):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(byte_string)
    hash_bytes = digest.finalize()
    return hash_bytes


# takes a key and ciphertext and returns the decrypted text using the 
# key
def asymmetric_decrypt(key, cipher):
    plaintext = key.decrypt(
        cipher,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))
    return plaintext


# Takes the concat
def symmetric_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypt_object = cipher.decryptor()
    decrypted_message = decrypt_object.update(ciphertext) + decrypt_object.finalize()
    while decrypted_message[len(decrypted_message) - 1:] == b' ':
        decrypted_message = decrypted_message[:-1]
    return decrypted_message


# Takes a file name and file contents, and writes said file contents to a
# file with the specified file name.
def write(file_name, file_contents):
    with open(file_name, 'a') as writer:
        writer.write(file_contents)


# takes bobs priate key and a symmetric key that has been encrypted with
# bobs public key, decrypts the symmetric key and returns the key and iv
def get_symmetric_key(bobs_private_key, encrypted_key):
    decrypted_key = asymmetric_decrypt(bobs_private_key, encrypted_key)
    # split the key between the key and the iv
    key = decrypted_key[0:32]
    iv = decrypted_key[32:]
    return iv, key


def validate_contents(contents, hash_bytes):
    comparison_hash_bytes = sha_256_hash(contents)
    if hash_bytes != comparison_hash_bytes:
        exit(0)
    else:
        print('Message hash checks out\n')


def handle(connection, bobs_priv, bobs_pub, cert_priv):
    try:

        # Receive the data in small chunks and retransmit it
        data = get_response(connection)
        print('Received:\n  {}\n'.format(data))
        # generate certificate
        certificate = generate_bobs_certificate(bobs_pub, cert_priv)
        print('Sending:\n  {}\n'.format(certificate))
        # send bob's certificate
        connection.sendall(certificate)
        # wait for response from Alice
        data = get_response(connection)
        print('Received:\n  {}\n'.format(data))
        # remove first and last two characters
        data = data[2:-2]
        # parse fields of message received
        data_fields = data.split(b'\', \'')
        # if the length of the data fields is less than
        # 3 or greater than 4, then the file had the wrong
        # number of fields
        bobs_private_key = load_private_key(bobs_priv)
        if len(data_fields) < 3 or 4 < len(data_fields):
            print('wrong number of fields returned')
            exit(0)
        elif len(data_fields) == 3:
            # parse message fields
            encrypted_message = base64.b64decode(data_fields[0].split(b'\': \'')[1])
            # get the encrypted key
            encrypted_key = base64.b64decode(data_fields[2].split(b'\': \'')[1])
            # get the bytes of the hash
            hash_bytes = base64.b64decode(data_fields[1].split(b'\': \'')[1])
            iv, key = get_symmetric_key(bobs_private_key, encrypted_key, )
            message = symmetric_decrypt(encrypted_message, key, iv)
            # if hash does not match exit else print message through the console
            # that the messages matched.
            validate_contents(encrypted_message, hash_bytes)
            print('Decoded message:\n  {}\n'.format(str(message, 'utf-8')))
        elif len(data_fields) == 4:
            # if the number of fields is 4 then we received a file
            # parse the fields of the datagram
            encrypted_file_name = base64.b64decode(data_fields[0].split(b'\': \'')[1])
            # get the contents of the file
            contents = base64.b64decode(data_fields[1].split(b'\': \'')[1])
            # get the hash of the file contents
            hash_bytes = base64.b64decode(data_fields[2].split(b'\': \'')[1])
            # get the encrypted key
            encrypted_key = base64.b64decode(data_fields[3].split(b'\': \'')[1])
            # get the hash to compare
            # decrypt the key using bobs private key
            iv, key = get_symmetric_key(bobs_private_key, encrypted_key)
            # decrypt the content of the file
            decrypted_content = symmetric_decrypt(contents, key, iv)
            # decrypt the name of the file
            file_name = symmetric_decrypt(encrypted_file_name, key, iv)
            # compare the hashes to ensure that the integrity of the message is not lost
            validate_contents(contents, hash_bytes)
            file_content = decrypted_content.decode('utf-8')
            # write the file to the file system
            write(file_name, file_content)
            print('File received and written to the file system')
    finally:
        print('--------------------------------------\n\n')
        print('closing socket')
        connection.close()
        exit(0)


# servers point of entry
def main():
    arguments = sys.argv
    num_arguments = len(arguments)
    if num_arguments != 6:
        print("Wrong number of arguments supplied")
        exit(0)
    port_no = int(arguments[2])
    bobs_private_key_filename = arguments[3].encode('utf-8')
    bobs_public_key_filename = arguments[4].encode('utf-8')
    certificate_agency_private = arguments[5].encode('utf-8')
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('--------------------------------------\n')
    # Bind the socket to the port
    sock.bind(('127.0.0.1', port_no))
    print('Waiting For Connection on 127.0.0.1 port {}\n'.format(str(port_no)))
    # Listen for incoming connections
    sock.listen(1)
    while True:

        # Wait for a connection
        connection, client_address = sock.accept()
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        handle(connection,
               bobs_private_key_filename,
               bobs_public_key_filename,
               certificate_agency_private)


if __name__ == "__main__":
    main()
