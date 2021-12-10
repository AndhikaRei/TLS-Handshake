# Import dependency.
import os
import sys
import socket
import rsa
import random
import string 
import json
from Crypto.Cipher import AES
from io import BufferedReader
from typing import List
from exception import FailedHandshakeError

# Import own module.
from segment import SEGMENT_TYPE, FLAGS, Segment, MAX_SIZE, MAX_SEGMENT, asciis_to_string, string_to_asciis

# 1 META, 2 DATA, 1 FIN (if applicable)
WINDOW_SIZE = 2
# Considering 32780B (262240b) is sent in 1m (actually 0m :v).
# With bandwidth 1MB/s
# The delay is 0.032s

# Generate Server Random String.   
RANDOM_STRING = ''.join(random.choices(string.ascii_lowercase + string.digits, k = 6))  \

# Server hello attributes.
TIMEOUT = 0.66
MAX_TRY = 5
TLS_VERSION = "1.0"
CRYPTO_ALGORITHM = "rsa"
DATA_COMPRESSION_METHOD = "vca"

# Server SSL Certificate.
SSL_CERTIFICATE =   '-----BEGIN CERTIFICATE-----MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i-----END CERTIFICATE-----'

# Generate server public and private key.
PUBLIC_KEY, PRIVATE_KEY = rsa.newkeys(128)
N = PUBLIC_KEY.__getattribute__('n')
E = PUBLIC_KEY.__getattribute__('e')

DIRNAME = os.path.dirname(__file__)
class Server:
    """
    Represents a UDP server
    """
    def __init__(self, ip: str, port: int, filename:str) -> None:
        # Generate socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((ip, port))
        self.clients = []
        self.socket.settimeout(30)
        self.filename = filename
        self.session_key = []
        self.client_random = []
        
        # Status of established client (client that finished tcp handshake).
        self.established_connection = []

        # Status of secured connection with client (Client that finished tls handshake).
        self.secureConnection = []
        
        # Status of client that ready to close connection. 
        self.ready_to_close_connection = []
        print(f'Server started at port {port}...')

    def listenForClients(self) -> None:
        """
        Function for listening to client.
        """

        # Loop for each listening client.
        done_listening = False
        while not done_listening:
            data, addr = self.socket.recvfrom(MAX_SEGMENT)
            if addr:
                print(f'[!] Client ({addr[0]}:{addr[1]}) found')
                self.clients.append(addr)
                
                more = input('[?] Listen more? (y/n) ').lower()
                while more != 'y' and more != 'n':
                    more = input('[?] Listen more? (y/n) ').lower()
                
                if more == 'n':
                    done_listening = True       
        print()
        print(f'{len(self.clients)} client(s) found:')
        for idx, client in enumerate(self.clients):
            print(f'{idx + 1}. {client[0]}:{client[1]}')
        
        # Set all client to not established, not secure, and not ready to close connection.
        self.established_connection = [0 for _ in range (len(self.clients))]
        self.secureConnection = [0 for _ in range (len(self.clients))]
        self.client_random = [0 for _ in range (len(self.clients))]
        self.session_key = [0 for _ in range (len(self.clients))]
        self.ready_to_close_connection = [0 for _ in range (len(self.clients))]

    def sendData(self, clientNum: int, file: BufferedReader) -> None:
        """
        Send data to client. Include handshaking process.
        """
        # Do Three way Handshake at first.
        # While connection has not been established then do TCP handshake.
        print(f'\nCommencing file transfer with client-{self.clients[clientNum][0]}:{self.clients[clientNum][1]}')
        
        print(f'Begin tcp handshake with client-{self.clients[clientNum][0]}:{self.clients[clientNum][1]}')
        while (self.established_connection[clientNum] == 0):
            # Construct and send SYN Segment.
            syn_segment = Segment("SYN", 0)
            success = self.sendSegmentHandshake(syn_segment, self.clients[clientNum])
            if (success != -1):
                # Construct and send ACK Segment
                Segment.verbose(syn_segment, "Acked")
                self.established_connection[clientNum] = 1
                print(f'Connection from client-{self.clients[clientNum][0]}:{self.clients[clientNum][1]} has been established')
                ack_segment = Segment(type="ACK", seq_number=1, ack_number=(success + 1))
                self.socket.sendto(ack_segment.to_bytes(), self.clients[clientNum])
                Segment.verbose(ack_segment, "Sent")
            else:
                break
        
        if (self.established_connection[clientNum] == 0):
            raise FailedHandshakeError

        print("TCP Handshake with client-"+str(self.clients[clientNum][0]) + ':' + str(self.clients[clientNum][1]) + " success\n")

        # Do TLS Handshake.
        # While connection not secure then do TLS Handshake.
        print(f'Begin TLS Handshake with client-{self.clients[clientNum][0]}:{self.clients[clientNum][1]}')
        while (self.secureConnection[clientNum] == 0):
            # Get client hello.
            raw_segment, _ = self.socket.recvfrom(MAX_SEGMENT)
            client_hello = Segment().from_bytes(raw_segment)
            Segment.verbose(client_hello, "Received", "Client hello segment")

            # Parse and validate client hello.
            client_hello_data = asciis_to_string(client_hello.data)
            
            client_hello_data = json.loads(client_hello_data)
            if (client_hello_data["tls_version"] == TLS_VERSION and 
                client_hello_data["crypto_algorithm"] == CRYPTO_ALGORITHM and 
                client_hello_data["data_compression_method"] == DATA_COMPRESSION_METHOD):

                print(f'Client-{self.clients[clientNum][0]}:{self.clients[clientNum][1]} hello message validated')
                
                #  Save client random.
                self.client_random[clientNum] = client_hello_data["random_string"]
                print(f'Client-{self.clients[clientNum][0]}:{self.clients[clientNum][1]} random string is {self.client_random[clientNum]}')
                # Do Server Hello message
                # Consruct Server Hello message segment.
                print("Constructing Server Hello message")
                data =  f'{{ "tls_version":"{TLS_VERSION}", ' \
                        f'"crypto_algorithm":"{CRYPTO_ALGORITHM}", ' \
                        f'"data_compression_method":"{DATA_COMPRESSION_METHOD}", ' \
                        f'"random_string":"{RANDOM_STRING}", '\
                        f'"ssl_certificate":"{SSL_CERTIFICATE}", '\
                        f'"public_key": {{"n":"{N}", "e":"{E}" }} }}'
                data = string_to_asciis(data)
                server_hello = Segment("DATA", 2, data=data)
                byte_segment = server_hello.to_bytes()

                # Send server Hello message segment to client and wait for client to send premaster key.
                self.socket.sendto(byte_segment, self.clients[clientNum])
                Segment.verbose(server_hello, "Sent", "Server hello segment")
                raw_segment, _ = self.socket.recvfrom(MAX_SEGMENT)
                client_premaster_key = Segment().from_bytes(raw_segment)
                Segment.verbose(client_premaster_key, "Received", "Client premaster key segment") 

                # Parse the premaster key and construct session key.
                client_premaster_key = rsa.decrypt(client_premaster_key.data, PRIVATE_KEY).decode()
                print(f'Client-{self.clients[clientNum][0]}:{self.clients[clientNum][1]} premaster key is {client_premaster_key}')
                self.session_key[clientNum] = bytearray((self.client_random[clientNum] + RANDOM_STRING + client_premaster_key).encode())
                AEScipher = AES.new(self.session_key[clientNum], AES.MODE_ECB)
                print(f'Session key with client-{self.clients[clientNum][0]}:{self.clients[clientNum][1]} is {self.session_key[clientNum].decode()}')

                # Wait for server to send finished message.
                raw_segment, _ = self.socket.recvfrom(MAX_SEGMENT)
                client_finished = Segment().from_bytes(raw_segment)
                Segment.verbose(client_finished, "Received", "Client change cipher spec segment")
                client_finished_data = AEScipher.decrypt(client_finished.data)

                # If client send finish message then send back the finish message also.
                if (client_finished_data == b'FINISH HANDSHAKE'):
                    data = AEScipher.encrypt(b'FINISH HANDSHAKE')
                    finish_segment = Segment("DATA", 3, data=data)
                    byte_segment = finish_segment.to_bytes()
                    self.socket.sendto(byte_segment, self.clients[clientNum])
                    Segment.verbose(finish_segment, "Sent", "Server change cipher spec segment")

                    # Wait for client to send acknowledgement.
                    raw_segment, address = self.socket.recvfrom(MAX_SEGMENT)
                    Segment.verbose(client_hello, "Received")
                    client_ack = Segment().from_bytes(raw_segment)
                    Segment.verbose(client_ack, "Received")
                    if (client_ack.is_ack and address == self.clients[clientNum]):
                        self.secureConnection[clientNum] = 1
                    break
                else :
                    print("Invalid session key exchange")
                    break
            break
        
        if (self.secureConnection[clientNum] == 0):
            raise FailedHandshakeError

        print("TLS Handshake with client-"+str(self.clients[clientNum][0]) + ':' + str(self.clients[clientNum][1]) + " success\n")
        self.socket.settimeout(TIMEOUT)

        # Sending data with goback-n.
        print(f'Begin sending metadata and data to client-{str(self.clients[clientNum][0])}:{str(self.clients[clientNum][1])}')
        Sb = 1               # Sequence number first segment
        starting_sequence_number = 1
        file_segments = Segment.from_file(file, self.filename, starting_sequence=starting_sequence_number)
        segment_to_send = 1
        
        while True:
            while segment_to_send < Sb + WINDOW_SIZE and segment_to_send <= len(file_segments):
                # First segmen are sequence number 1 but with index 0
                target_segment = file_segments[segment_to_send - 1]  
                byte_segment = target_segment.to_bytes()
                self.socket.sendto(byte_segment, self.clients[clientNum])
                Segment.verbose(target_segment, "Sent")
                segment_to_send += 1
            
            try:
                raw, address = self.socket.recvfrom(MAX_SEGMENT)
                ack = Segment().from_bytes(raw)
                if (ack.is_ack and ack.ack >= Sb and address == self.clients[clientNum]):
                    Segment.verbose(ack, "Acked")
                    Sb = ack.ack + 1
                    if Sb > (file_segments[len(file_segments) - 1].sequence):
                        # Last segment sent
                        break
            except socket.timeout:
                Segment.verbose(file_segments[Sb-1], f"No ACK received, retry sending from sequence {Sb}" )
                segment_to_send = Sb

        # Send FIN segment after all data has been send.
        fin_sequence = (file_segments[len(file_segments) - 1].sequence)+1
        fin_segment = Segment("FIN", fin_sequence)
        acknum = self.sendSegment(fin_segment, self.clients[clientNum])
        print(f'Sending data to client-{self.clients[clientNum][0]}:{self.clients[clientNum][1]} success\n')
        self.socket.settimeout(30)
        # If client still not ready to close connection.
        while (self.ready_to_close_connection[clientNum] == 0):
        # Wait for finack segment from client.
            raw_segment, address = self.socket.recvfrom(MAX_SEGMENT)
            segment = Segment().from_bytes(raw_segment)
            if (segment.is_finack and segment.sequence == 1 and segment.ack == acknum and address == self.clients[clientNum]):
                self.ready_to_close_connection[clientNum] = 1
                print(f'Inform client-{self.clients[clientNum][0]}:{self.clients[clientNum][1]} to close connection \n')
                self.closeConnection(clientNum, fin_sequence)

    def sendSegment(self, segment:Segment, address:List[int])->int:
        """
        Send segment and wait for the receiver to ack it, if not acked then send again until acked.
        """
        # Convert segment to bytes and sending initialization.
        byte_segment = segment.to_bytes()
        try_send = 0

        segment2 = Segment()
        
        # Send segment and parse receive the result.
        # While received segment is not valid and num of try is still less than max try then send again segment.
        while (try_send < MAX_TRY and (not(segment2.is_ack) or segment2.ack != segment.sequence+1 or address2 != address)):
            try:
                self.socket.sendto(byte_segment, address)
                Segment.verbose(segment, "Sent")
                try_send += 1
                raw_segment2, address2 = self.socket.recvfrom(MAX_SEGMENT)
                segment2 = Segment().from_bytes(raw_segment2)
            except socket.timeout:
                Segment.verbose(segment, f"No ACK received, retry sending" )
        
        if (try_send == MAX_TRY):
            raise Exception("Max send try is already reached")
        
        Segment.verbose(segment, "Acked")
        return segment2.ack

    def sendSegmentHandshake(self, segment:Segment, address:List[int])->int:
        """
        Send segment to specific address for handshake, if send success return segment received seqnum. If Failed return -1.
        """
        byte_segment = segment.to_bytes()
        try:
            # Send segment and get the returned segment.
            self.socket.sendto(byte_segment, address)
            Segment.verbose(segment, "Sent")
            raw_segment2, address2 = self.socket.recvfrom(MAX_SEGMENT)
            
            # Parse and validate segment.
            segment2 = Segment().from_bytes(raw_segment2)
            if (segment.is_syn and segment2.is_synack and segment2.ack == segment.sequence + 1 and address2 == address):
                return segment2.sequence
            return -1
        except socket.timeout :
            print("Failed to send packet")
            return -1
        
    def closeConnection(self, clientNum, finSeq)->None:
        """
        Close connection of server, but must make sure every client connection must be stopped first.
        """
        ack_segment = Segment("ACK", seq_number=finSeq+1 , ack_number=2)
        byte_segment = ack_segment.to_bytes()
        self.socket.sendto(byte_segment, self.clients[clientNum])
        Segment.verbose(ack_segment, "Sent")
        print("Client-"+ str(self.clients[clientNum][0]) + ':' + str(self.clients[clientNum][1])+" socket has been closed")

def main(argv):
    if len(argv) < 2:
        sys.exit('Must specify port number and filename to be sent')
    try:
        int(argv[0])
    except:
        sys.exit('Port must be a number!')
    try:
        file_exist = os.path.isfile(os.path.join(DIRNAME, argv[1]))
        if (file_exist):
            file = open(os.path.join(DIRNAME, argv[1]), 'rb')
            filename, file_extension = os.path.splitext(os.path.basename(argv[1]))
        else: 
            raise Exception()
    except:
        sys.exit('File does not exist!')

    server = Server('127.0.0.255', int(argv[0]), filename+file_extension)

    print('Listening to broadcast address for clients.\n')
    server.listenForClients()

    for i in range(len(server.clients)):
        try:
            server.sendData(i, file)
        except FailedHandshakeError:
            print(f'Failed to handshake with client-{server.clients[i][0]}:{server.clients[i][1]}')
            pass
    print("Sending data to all/partial client success\n")
    
    print("Gracefully closed all connection\n")
    server.socket.close()
    file.close()
    
if __name__ == '__main__':
    main(sys.argv[1:])
