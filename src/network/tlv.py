import struct
import json
import socket

# Types de messages TLV
TYPE_PEER_LIST = 1
TYPE_PING = 2
TYPE_PONG = 3
TYPE_HANDSHAKE_HELLO = 4
TYPE_HANDSHAKE_REPLY = 5
TYPE_HANDSHAKE_AUTH = 6
TYPE_HANDSHAKE_OK = 7
TYPE_SECURE_MSG = 8
TYPE_CHAT_MSG = 9
TYPE_MANIFEST = 10
TYPE_CHUNK_REQ = 11
TYPE_CHUNK_DATA = 12
TYPE_CHUNK_ACK = 13

def encode_tlv(msg_type: int, payload: dict = None) -> bytes:
    """Encode un message au format Type-Length-Value."""
    if payload is None:
        data = b''
    else:
        data = json.dumps(payload).encode('utf-8')
    
    # 1 byte pour le type, 4 bytes (unsigned int, big-endian) pour la longueur
    header = struct.pack('!BI', msg_type, len(data))
    return header + data

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Lit exactement n octets depuis la socket."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None # Connexion fermée
        data.extend(packet)
    return bytes(data)

def decode_tlv(sock: socket.socket):
    """Lit et décode un message TLV complet depuis la socket. Retourne (msg_type, payload)."""
    header = recv_exact(sock, 5)
    if not header:
        return None, None
        
    msg_type, length = struct.unpack('!BI', header)
    
    if length > 0:
        data = recv_exact(sock, length)
        if not data:
            return None, None
        try:
            payload = json.loads(data.decode('utf-8'))
        except json.JSONDecodeError:
            payload = {}
    else:
        payload = {}
        
    return msg_type, payload
