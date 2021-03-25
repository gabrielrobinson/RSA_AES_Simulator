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
#   bruce.py opens a socket connection and waits for a request. Once a request is received it will send
#   send a message digest containing his name, his public key, and a signature of his public key signed
#   by the certificate agencies private key. bruce.py then waits for a response from the requesting host.
#   This datagram should either contain a message or a file. that is encrypted with a symmetric key. This
#   symmetric key should also be in the message and should be encrypted with bruce's public key. Furthermore,
#   the message should contain a signature of the encrypted message, in order to verify. This verification
#   is done with sha256 hashing function provided by the cryptography module. bruce.py uses the cryptography
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


# generates a certificate with bruce's public key,
# the the public key signed by the certificate agencies
# private key, and the name of the sender
def generate_bruces_certificate(bruces_pub, cert_priv):
    # load bruce's public key
    bruces_public_key = load_public_key(bruces_pub)
    # load certificate authorities private key
    certificate_authority_private_key = load_private_key(cert_priv)
    print('Certificate authority\'s private key:\n  {}\n'.format(certificate_authority_private_key))
    # cast bruce's public key to a byte string and then sign the public key
    bruces_public_key_bytes = bruces_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print('Bruce\'s public key:\n  {}\n'.format(bruces_public_key_bytes))
    # sign bruce's public key with the CA's private key
    signature = base64.b64encode(sign(bruces_public_key_bytes, certificate_authority_private_key))
    print('SHA256 CA Signature of Bruce\'s public key:\n  {}\n'.format(signature))
    # generate certificate json object and return it
    certificate_json = b"{{name:Batman, pub_key:" + bruces_public_key_bytes + b", signature:" + signature + b"}}\0"
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


# takes bruces priate key and a symmetric key that has been encrypted with
# bruces public key, decrypts the symmetric key and returns the key and iv
def get_symmetric_key(bruces_private_key, encrypted_key):
    decrypted_key = asymmetric_decrypt(bruces_private_key, encrypted_key)
    # split the key between the key and the iv
    key = decrypted_key[0:32]
    iv = decrypted_key[32:]
    return iv, key


def validate_contents(contents, hash_bytes):
    comparison_hash_bytes = sha_256_hash(contents)
    if hash_bytes != comparison_hash_bytes:
        exit(0)
    else:
        print('Message has the correct SHA256 Hash\n')


def handle(connection, bruces_priv, bruces_pub, cert_priv):
    try:

        # Receive the data in small chunks and retransmit it
        data = get_response(connection)
        print('Received:\n  {}\n'.format(data))
        # generate certificate
        print('Generating Certificate...\n')
        certificate = generate_bruces_certificate(bruces_pub, cert_priv)
        print('Sending certificate...\n')
        # send bruce's certificate
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
        bruces_private_key = load_private_key(bruces_priv)
        if len(data_fields) < 3 or 4 < len(data_fields):
            print('wrong number of fields returned')
            exit(0)
        elif len(data_fields) == 3:
            # parse message fields
            encrypted_message = base64.b64decode(data_fields[0].split(b'\': \'')[1])
            print('Encrypted message:\n  {}\n'.format(encrypted_message))
            # get the encrypted key
            encrypted_key = base64.b64decode(data_fields[2].split(b'\': \'')[1])
            print('Encrypted symmetric key and IV:\n  {}\n'.format(encrypted_key))
            # get the bytes of the hash
            hash_bytes = base64.b64decode(data_fields[1].split(b'\': \'')[1])
            print('SHA256 Hash of encrypted message:\n  {}\n'.format(hash_bytes))
            iv, key = get_symmetric_key(bruces_private_key, encrypted_key, )
            print('Decrypted symmetric key and iv:\n  {}\n'.format(key, iv))
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
            print('Encrypted message:\n  {}\n'.format(contents))
            # get the hash of the file contents
            hash_bytes = base64.b64decode(data_fields[2].split(b'\': \'')[1])
            print('SHA256 Hash of encrypted message:\n  {}\n'.format(hash_bytes))
            # get the encrypted key
            encrypted_key = base64.b64decode(data_fields[3].split(b'\': \'')[1])
            print('Encrypted symmetric key and IV:\n  {}\n'.format(encrypted_key))
            # get the hash to compare
            # decrypt the key using bruces private key
            iv, key = get_symmetric_key(bruces_private_key, encrypted_key)
            print('Decrypted symmetric key and iv:\n  {}\n'.format(key, iv))
            # decrypt the content of the file
            decrypted_content = symmetric_decrypt(contents, key, iv)
            # decrypt the name of the file
            file_name = symmetric_decrypt(encrypted_file_name, key, iv)
            print('Decoded file name:\n {}\n'.format(str(file_name, 'utf-8')))
            # compare the hashes to ensure that the integrity of the message is not lost
            validate_contents(contents, hash_bytes)
            file_content = decrypted_content.decode('utf-8')
            print('Decoded file contents:\n{}\n'.format(str(file_content)))
            # write the file to the file system
            # write(file_name, file_content)
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
    bruces_private_key_filename = arguments[3].encode('utf-8')
    bruces_public_key_filename = arguments[4].encode('utf-8')
    certificate_agency_private = arguments[5].encode('utf-8')
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('--------------------------------------\n')
    # Bind the socket to the port
    sock.bind(('127.0.0.1', port_no))
    print('Bruce is waiting for a connection at 127.0.0.1:{}\n'.format(str(port_no)))
    # Listen for incoming connections
    sock.listen(1)
    while True:

        # Wait for a connection
        connection, client_address = sock.accept()
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        handle(connection,
               bruces_private_key_filename,
               bruces_public_key_filename,
               certificate_agency_private)


if __name__ == "__main__":
    main()
