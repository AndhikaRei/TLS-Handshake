import sys
import socket
import os
import string    
import random
import json 
import rsa
from typing import List
from sys import byteorder
from Crypto.Cipher import AES

# Import own module.
from segment import SEGMENT_TYPE, FLAGS, Segment, MAX_SIZE, MAX_SEGMENT, string_to_asciis, asciis_to_string

MAX_TRY = 5
DIRNAME = os.path.dirname(__file__)

# TLS handshake property. 
TLS_VERSION = "1.0"
CRYPTO_ALGORITHM = "rsa"
DATA_COMPRESSION_METHOD = "vca"
SSL_CERTIFICATE =   '-----BEGIN CERTIFICATE-----MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i-----END CERTIFICATE-----'

# Generate Client Random String.   
RANDOM_STRING = ''.join(random.choices(string.ascii_lowercase + string.digits, k = 5))  
RANDOM_STRING_2 = ''.join(random.choices(string.ascii_lowercase + string.digits, k = 5))    

# Generate Client Private and Public Key.
PUBLIC_KEY, PRIVATE_KEY = rsa.newkeys(128)

class Client:
    """
    Represents a UDP client
    """
    def __init__(self, ip: str, port: int, server_port: int, filename:str, use_meta:bool) -> None:
        self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.socket.bind((ip, port))
        self.socket.settimeout(30)
        self.connection_established = False
        self.secure_connection = False
        self.filename = filename
        self.use_meta = use_meta
        self.server_port = server_port
        self.session_key = bytearray()
        print(f'Client started at port {port}...')
        
    def request(self) -> None:
        self.socket.sendto(b'request', ('127.0.0.255', self.server_port))
        print("Sent request to broadcast address")
    
    def receiveFile(self) -> None:
        """
        Receive data from server. Include handshaking process.
        """
        # Do Three way Handshake at first.
        # While connection has not been established then do handshake.
        print("Begin handshaking with server\n")
        print("Begin TCP Handshake with server")
        while (not self.connection_established):
            # Get syn segment from server.
            raw_segment, address = self.socket.recvfrom(MAX_SEGMENT)
            # Parse and validate segment.
            segment = Segment().from_bytes(raw_segment)
            print(f'[Segment SEQ={segment.sequence}] Received')
            if (segment.is_syn):
                segment.ack = segment.sequence + 1
                segment.sequence = 0
                segment.flags = FLAGS[SEGMENT_TYPE.SYNACK]
                self.sendSegmentHandshake(segment, address)
        
        print("Connection with server established \n")

        # Begin TLS handshake with server.
        print("Begin TLS handshake with server")
        while (not self.secure_connection):
            # Do Client Hello message
            # Consruct Client Hello message segment.
            print("Generating Client Hello message")
            data =  f'{{ "tls_version":"{TLS_VERSION}", ' \
                    f'"crypto_algorithm":"{CRYPTO_ALGORITHM}", ' \
                    f'"data_compression_method":"{DATA_COMPRESSION_METHOD}", ' \
                    f'"random_string":"{RANDOM_STRING}" }}'
            print("Client random string is" + RANDOM_STRING)
            data = string_to_asciis(data)
            client_hello = Segment("DATA", 1, data=data)
            byte_segment = client_hello.to_bytes()

            # Send Client Hello message segment to server and wait for server to send server hello.
            server_hello = Segment()
            self.socket.sendto(byte_segment, address)
            Segment.verbose(client_hello, "Sent", "Client hello segment")
            raw_segment, _ = self.socket.recvfrom(MAX_SEGMENT)
            server_hello = Segment().from_bytes(raw_segment)
            Segment.verbose(server_hello, "Received", "Server hello segment") 
            
            # Get the server hello data then parse and validate it.
            # This is called authentication phase
            server_hello_data = asciis_to_string(server_hello.data)
            server_hello_data = json.loads(server_hello_data)
            if (server_hello_data["tls_version"] == TLS_VERSION and 
                server_hello_data["crypto_algorithm"] == CRYPTO_ALGORITHM and 
                server_hello_data["data_compression_method"] == DATA_COMPRESSION_METHOD and 
                server_hello_data["ssl_certificate"] == SSL_CERTIFICATE):
                
                print("Server hello message validated")

                # Get server public key.
                pub = server_hello_data["public_key"]
                server_random:str = server_hello_data["random_string"]
                print("Server random message is " + server_random)
                self.server_public_key = rsa.PublicKey(n=int(pub['n']), e=int(pub['e']))
                
                # Do premaster secret phase.
                # Send another random secret key encprypted with client public key.
                print("Client premaster key is " + RANDOM_STRING_2)
                data = rsa.encrypt(RANDOM_STRING_2.encode(), self.server_public_key)
                premaster_segment = Segment("DATA", 2, data=data)
                byte_segment = premaster_segment.to_bytes()

                # Send premaster secret segment to server.
                self.socket.sendto(byte_segment, address)
                Segment.verbose(premaster_segment, "Sent", "Client encrypted premaster key segment")

                # Consteuct Session Key.
                self.session_key = bytearray((RANDOM_STRING + server_random + RANDOM_STRING_2).encode())
                print("Session key with server is " + self.session_key.decode())
                AEScipher = AES.new(self.session_key, AES.MODE_ECB)

                # Send encrypted finish message to server using session key.
                data = AEScipher.encrypt(b'FINISH HANDSHAKE')
                finish_segment = Segment("DATA", 0, data=data)
                byte_segment = finish_segment.to_bytes()
                self.socket.sendto(byte_segment, address)
                Segment.verbose(finish_segment, "Sent", "Client change cipher spec")
                
                # Then wait for server to send same message back.
                raw_segment, _ = self.socket.recvfrom(MAX_SEGMENT)
                Segment.verbose(finish_segment, "Received")
                finish_segment = Segment().from_bytes(raw_segment)
                Segment.verbose(finish_segment, "Received", "Server change cipher spec")
                finish_segment_data = AEScipher.decrypt(finish_segment.data)

                # If server sends same message back then connection is secure.
                if (finish_segment_data == b'FINISH HANDSHAKE'):
                    self.secure_connection = True
                    print("Secure Connection Established")
                    ack_segment = Segment(type="ACK", seq_number=3, ack_number=(0))
                    self.socket.sendto(ack_segment.to_bytes(), address)
                    Segment.verbose(ack_segment, "Sent")
                else :
                    print("Invalid session key exchange")
                    return
            else:
                print("Invalid server hello message")
                return
            
        print("Secure connection with server established")
        
        self.socket.settimeout(30)

        print("Begin receiving data")
        # GOBACK N
        Rn = 1
        filename = ''
        cumulatedData: bytearray = bytearray()
        while True:
            raw, address = self.socket.recvfrom(MAX_SEGMENT)
            segment = Segment().from_bytes(raw)
            Segment.verbose(segment, "Received")
            if segment.sequence == Rn and segment.valid:
                if segment.is_meta:
                    filename = filename + asciis_to_string(segment.data)
                    ack_segment = Segment(seq_number=segment.sequence, ack_number=segment.sequence, type=SEGMENT_TYPE.ACK)
                    self.socket.sendto(ack_segment.to_bytes(), address)
                    segment.verbose(ack_segment, "Sent")
                elif segment.is_data:
                    cumulatedData += bytearray(segment.data)
                    ack_segment = Segment(seq_number=segment.sequence, ack_number=segment.sequence, type=SEGMENT_TYPE.ACK)
                    self.socket.sendto(ack_segment.to_bytes(), address)
                    segment.verbose(ack_segment, "Sent")
                elif segment.is_fin:
                    print("Data received successfully \n")
                    
                    # Write file.
                    print("Writing file.....")
                    if self.use_meta:
                        file = open(os.path.join(DIRNAME, self.filename+filename), 'wb')
                    else:
                        file = open(os.path.join(DIRNAME, self.filename), 'wb')
                    file.write(cumulatedData)
                    print("File written succesfully")

                    # Tearing down connection.
                    print("Begin to tear down connection")
                    segment.ack = segment.sequence + 1
                    segment.sequence = 1
                    segment.flags = FLAGS[SEGMENT_TYPE.ACK]
                    byte_segment = segment.to_bytes()
                    self.socket.sendto(byte_segment, address)

                    # Sending fin to server to state that our server is ready to close
                    self.socket.settimeout(2)
                    finack_segment = Segment(SEGMENT_TYPE.FINACK, segment.sequence, segment.ack)
                    ack_num = self.sendSegment(finack_segment, address)
                    self.socket.settimeout(30)

                    if (ack_num == 2):
                        self.closeConnection()
                        file.close()
                        break
                Rn += 1
            else:
                # If rejected then send back last acquired ack segment.
                Segment.verbose(segment, "Rejected")
                ack_segment = Segment(seq_number=Rn-1, ack_number=Rn-1, type=SEGMENT_TYPE.ACK)
                self.socket.sendto(ack_segment.to_bytes(), address)
                segment.verbose(ack_segment, "Sent")
           
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
        
        print(f'[Segment SEQ={segment.sequence}] Acked')
        return segment2.ack

    def sendSegmentHandshake(self, segment:Segment, address:List[int])->None:
        """
        Send segment to specific address for handshake.
        """
        byte_segment = segment.to_bytes()

        # Send segment and get the returned segment.
        self.socket.sendto(byte_segment, address)
        Segment.verbose(segment, "Sent")
        raw_segment2, _ = self.socket.recvfrom(MAX_SEGMENT)
        # Parse and validate segment.
        segment2 = Segment().from_bytes(raw_segment2)
        if (segment.is_synack and segment2.is_ack and segment2.ack == segment.sequence+1):
            Segment.verbose(segment2, "Received")
            self.connection_established = True 
    
    def closeConnection(self)->None:
        """
        Gracefully closing connection with server.
        """
        print("Begin closing connection")
        self.socket.close()
        print("Connection closed")


def main(argv):
    if len(argv) < 3:
        sys.exit('Must specify two port number and path to save file')
    try:
        int(argv[0])
        int(argv[1])
    except:
        sys.exit('Port must be a number')
    
    try:
        filename = str(argv[2])
        os.makedirs(os.path.dirname(filename), exist_ok=True)
    except:
        pass
    
    # Asking for using file metadata or not.
    use_meta = False
    directory = None
    while directory != 'y' and directory != 'n':
        directory = input('[?] Use file metadata? (y/n) ').lower()
        if directory =='y': use_meta = True
    if use_meta and not(os.path.isdir(filename)):
        sys.exit("path to file must be a directory")
    if not(use_meta) and os.path.isdir(filename):
        sys.exit("path to file must be a file")

    print('Connecting to server......')
    client = Client('127.0.0.1', int(argv[0]), int(argv[1]), filename, use_meta)
    client.request()

    print('Begin to get file.....')
    client.receiveFile()

if __name__ == '__main__':
    main(sys.argv[1:])