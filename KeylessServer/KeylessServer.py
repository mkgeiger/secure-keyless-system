#!/usr/bin/python3

import os
import threading
import signal
import sys
import time
from enum import Enum
from datetime import datetime
from OpenSSL import crypto
import hashlib
import socket
import struct
import binascii
import select
from multiprocessing import Process, Value, Queue
from monotoniccounter import *
import RPi.GPIO as GPIO

class MessageId(Enum):
    REQUEST_SERVICE_MSG           = 0x40
    SIGNATURE_MSG                 = 0x41

class RequestServiceResponseCode(Enum):
    VALID_CHALLENGE               = 0x60
    UNEXPECTED_ERROR_OCCURED_1    = 0x61
    VALUE_ERROR                   = 0x62
    ERROR_LOADING_CERTIFICATE     = 0x63
    INVALID_CA_AUTHENTICATION     = 0x64
    INVALID_CERTIFICATE_DATA      = 0x65
    EXPIRED_CERTIFICATE           = 0x66
    TIME_DELAY_NOT_EXPIRED        = 0x67
    REVOKED_CERTIFICATE           = 0x68

class SignatureResponseCode(Enum):
    AUTHORIZATION_GRANTED         = 0x70
    UNEXPECTED_ERROR_OCCURED_2    = 0x71
    SIGNATURE_VERIFICATION_FAILED = 0x72

sock = None
public_key = None
nonce_bytes = None

def signal_handler(sig, frame):
    global sock
    if sock:
        print("\nCtrl+C detected! Closing the socket.")
        sock.close()
    sys.exit(0)

def unlock_function():
    # Here comes the individual unlock code, the following is just an example to demonstrate it with the onboard LED
    GPIO.output(47, GPIO.LOW)
    time.sleep(0.5)
    GPIO.output(47, GPIO.HIGH)

def receive_message(client_socket):
    raw_msgid = receive_all(client_socket, 1);
    if not raw_msgid:
        return None, None
    msgid = struct.unpack('!B', raw_msgid)[0]
    #print("Message ID: ", msgid)
    raw_msglen = receive_all(client_socket, 2);
    if not raw_msglen:
        return None, None
    msglen = struct.unpack('!H', raw_msglen)[0]
    #print("Message length: ", msglen)
    msg = receive_all(client_socket, msglen)
    #if msg is not None:
    #    print("Message payload: ", binascii.hexlify(bytearray(msg)))
    return msgid, msg

def receive_all(client_socket, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = client_socket.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def send_message(client_socket, msgid, message):
    # Prefix each message with a 4-byte length (network byte order)
    message_id = struct.pack('!B', msgid)
    if message == None:
        client_socket.sendall(message_id)
    else:
        message_length = struct.pack('!H', len(message))
        client_socket.sendall(message_id + message_length + message)

def print_common_name(cert):
    # Get the subject of the certificate
    subject = cert.get_subject()

    # Extract the common name (CN) from the subject
    common_name = None
    for name, value in subject.get_components():
        if name == b'CN':
            common_name = value.decode()
            break

    # Print the common name
    if common_name:
        print("Common Name (CN):", common_name)
    else:
        print("Common Name (CN) not found in the certificate.")

def print_serial_number(cert):
    # Get the subject of the certificate
    subject = cert.get_subject()

    # Get the Serial Number value from the subject
    serial_number = None
    for name, value in subject.get_components():
        if name == b'serialNumber':  # OID for Serial Number attribute
            serial_number = value
            break

    # Print the serial number
    if serial_number:
        print("Serial Number:", binascii.hexlify(bytearray(serial_number)))
    else:
        print("Serial Number not found in the certificate.")

def get_certificate_dates(cert):
    try:
        # Retrieve the "not before" and "not after" dates
        not_before = cert.get_notBefore().decode('utf-8')
        not_after = cert.get_notAfter().decode('utf-8')
        return not_before, not_after
    except:
        return None, None

def worker_process(message_queue, is_delayed):
    global public_key
    global nonce_bytes

    state = 0

    # create a secure monotonic up-counter
    counter = SecureMonotonicCounter()

    # load CA certificate
    with open("ca.crt", 'rb') as f:
        ca_cert_pem = f.read()
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)

    # Create a certificate store and add the CA certificate
    store = crypto.X509Store()
    store.add_cert(ca_cert)

    while True:
        try:
            # Check for messages from the main process
            if not message_queue.empty():
                client_socket, address, message = message_queue.get()

                if ((message[0] == MessageId.REQUEST_SERVICE_MSG.value) and (state == 0)):

                    # Following code lines are for testing only
                    #is_delayed.value = True
                    #time.sleep(10)
                    #is_delayed.value = False

                    # loading and verfying the user certificate
                    user_cert_der = message[1]
                    #print("User Certificate: ", binascii.hexlify(bytearray(user_cert_der)))

                    try:
                        user_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, user_cert_der)
                        # Create a store context with the certificate to be verified and the store
                        store_ctx = crypto.X509StoreContext(store, user_cert)
                        # Perform the verification
                        store_ctx.verify_certificate()
                        print("Certificate is valid and signed by the CA.")
                    except crypto.Error as e:
                        print("Error in OpenSSL loading the user certificate:", e)
                        send_message(client_socket, RequestServiceResponseCode.ERROR_LOADING_CERTIFICATE.value, None)
                        state = 0
                        continue
                    except crypto.X509StoreContextError as e:
                        print("Certificate verification failed:", e)
                        send_message(client_socket, RequestServiceResponseCode.INVALID_CA_AUTHENTICATION.value, None)
                        state = 0
                        continue
                    except ValueError as e:
                        print("Value Error for loading the user certificate:", e)
                        send_message(client_socket, RequestServiceResponseCode.VALUE_ERROR.value, None)
                        state = 0
                        continue
                    except Exception as e:
                        print("An unexpected error occurred while loading user certificate:", e)
                        send_message(client_socket, RequestServiceResponseCode.UNEXPECTED_ERROR_OCCURED_1.value, None)
                        state = 0
                        continue

                    #print_common_name(user_cert)
                    #print_serial_number(user_cert)

                    # Retrieve the "not before" and "not after" dates
                    not_before, not_after = get_certificate_dates(user_cert)
                    if ((not_before == None) and (not_after == None)):
                        print("Invalid NotBefore/NotAfter data:")
                        send_message(client_socket, RequestServiceResponseCode.INVALID_CERTIFICATE_DATA.value, None)
                        state = 0
                        continue

                    # Convert dates to datetime objects
                    not_before_dt = datetime.strptime(not_before, "%Y%m%d%H%M%SZ")
                    not_after_dt = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")

                    # Get the current time
                    current_time = datetime.now()

                    # Check if the current time is within the validity period of the certificate
                    if ((current_time < not_before_dt) or (current_time > not_after_dt)):
                        print("Certificate has expired.")
                        send_message(client_socket, RequestServiceResponseCode.EXPIRED_CERTIFICATE.value, None)
                        state = 0
                        continue
                    else:
                        print("Certificate within validity period.")

                    # Extract the public key
                    try:
                        public_key = user_cert.get_pubkey()
                    except Exception as e:
                        print("An error occurred while retrieving the public key:", e)
                        send_message(client_socket, RequestServiceResponseCode.INVALID_CERTIFICATE_DATA.value, None)
                        state = 0
                        continue

                    # Generate 28 byte random number
                    try:
                        random_number_bytes = os.urandom(28)
                    except:
                        print("An unexpected error occurred while generating the random number.")
                        send_message(client_socket, RequestServiceResponseCode.UNEXPECTED_ERROR_OCCURED_1.value, None)
                        state = 0
                        continue

                    # increment monotonic counter
                    counter_bytes = struct.pack('!I', counter.increment())

                    # create nonce (32 bytes)
                    nonce_bytes = counter_bytes + random_number_bytes

                    # generate SHA256 of nonce
                    try:
                        sha256 = hashlib.sha256()
                        sha256.update(nonce_bytes)
                        nonce_digest = sha256.hexdigest()
                    except TypeError as e:
                        print("An type error occurred while computing SHA-256 digest:", e)
                        send_message(client_socket, RequestServiceResponseCode.INVALID_CERTIFICATE_DATA.value, None)
                        state = 0
                        continue
                    except Exception as e:
                        print("An unexpected error occurred while computing SHA-256 digest:", e)
                        send_message(client_socket, RequestServiceResponseCode.UNEXPECTED_ERROR_OCCURED_1.value, None)
                        state = 0
                        continue

                    nonce_digest_bytes = bytes.fromhex(nonce_digest)
                    #print("Nonce hash: ", binascii.hexlify(bytearray(nonce_digest_bytes)))

                    send_message(client_socket, RequestServiceResponseCode.VALID_CHALLENGE.value, nonce_digest_bytes)
                    state = 1

                if ((message[0] == MessageId.SIGNATURE_MSG.value) and (state == 1)):
                    signature = message[1]
                    #print("Signature: ", binascii.hexlify(bytearray(signature)))

                    # the verify() function expects that the public key is wrapped in an X.509 certificate
                    try:
                        x509 = crypto.X509()
                        x509.set_pubkey(public_key)
                        crypto.verify(x509, signature, nonce_bytes, "sha256")
                        send_message(client_socket, SignatureResponseCode.AUTHORIZATION_GRANTED.value, None)
                        print("Signature is valid.")

                        # Create and start unlock thread
                        unlock_thread = threading.Thread(target=unlock_function)
                        unlock_thread.start()
                    except crypto.Error as e:
                        print("Signature is invalid:", e)
                        send_message(client_socket, SignatureResponseCode.SIGNATURE_VERIFICATION_FAILED.value, None)
                    except Exception as e:
                        print("An unexpected error occurred while verifying the signature:", e)
                        send_message(client_socket, SignatureResponseCode.UNEXPECTED_ERROR_OCCURED_2.value, None)
                    state = 0

        except KeyboardInterrupt:
            break

def setup_server_socket():
    # Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Ensure that you can restart your server quickly when it terminates
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Set the client socket's TCP "well-known port" number
    well_known_port = 8881
    sock.bind(('', well_known_port))

    # Set the number of clients waiting for connection that can be queued
    sock.listen(1)

    print(f"Server is listening on port {well_known_port}")
    return sock

def main():
    global sock

    # Init signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Onboard LED GPIO initialization
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    GPIO.setup(47, GPIO.OUT)
    GPIO.output(47, GPIO.HIGH)

    # Queue for inter-process communication
    message_queue = Queue()
    is_delayed = Value('b', False)  # Shared boolean variable

    sock = setup_server_socket()

    # Start the sleep subprocess
    p = Process(target=worker_process, args=(message_queue, is_delayed))
    p.start()

    # Loop waiting for connections (terminate with Ctrl-C)
    try:
        while True:
            # Use select to wait for incoming connections or handle signals
            readable, _, _ = select.select([sock], [], [], 1)

            if not readable:
                print("Sock Timeout occurred")
                # Timeout occurred
                continue

            if sock in readable:
                newSocket, address = sock.accept()
                print("Connected from", address)

                # Loop serving the new client
                try:
                    while True:
                        readable, _, _ = select.select([newSocket], [], [], 1)

                        if not readable:
                            print("newSocket Timeout occurred")
                            # Timeout occurred
                            continue

                        if newSocket in readable:
                            message = receive_message(newSocket)
                            if ((message[0] == None) or (message[1] == None)):
                                break

                            if is_delayed.value:
                                print("Busy !!!!!!!!!!!!!!")
                            else:
                                message_queue.put((newSocket, address, message))

                except socket.error as e:
                    print(f"Socket error with client {address}: {e}")

                finally:
                    newSocket.close()
                    print("Disconnected from", address)
    except socket.error as e:
        print(f"Socket error: {e}. Reinitializing socket...")
        sock.close()
        sock = setup_server_socket()
    except KeyboardInterrupt:
        print("\nCaught KeyboardInterrupt. Exiting gracefully.")
    finally:
        if sock:
            sock.close()
        if p.is_alive():
            p.terminate()
            p.join()
        print("Socket closed.")

if __name__ == "__main__":
    main()
