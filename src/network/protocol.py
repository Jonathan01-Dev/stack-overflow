import struct
import hashlib
import hmac
import json

class ArchipelPacket:
    """
    Representation of an Archipel Packet v1.
    
    Structure:
    - MAGIC (4 bytes): 'ARCH'
    - TYPE (1 byte): 0x01 to 0x07
    - NODE_ID (32 bytes): Ed25519 Public Key (Raw bytes)
    - PAYLOAD_LEN (4 bytes): uint32 (Big Endian)
    - PAYLOAD (variable): Encrypted data
    - HMAC-SHA256 (32 bytes): Signature of the entire packet above
    """
    
    MAGIC = b'ARCH'
    HEADER_SIZE = 4 + 1 + 32 + 4 # 41 bytes
    FOOTER_SIZE = 32 # HMAC-SHA256
    
    # Types
    TYPE_HELLO = 0x01
    TYPE_PEER_LIST = 0x02
    TYPE_MSG = 0x03
    TYPE_CHUNK_REQ = 0x04
    TYPE_CHUNK_DATA = 0x05
    TYPE_MANIFEST = 0x06
    TYPE_ACK = 0x07
    
    def __init__(self, msg_type: int, node_id: bytes, payload: bytes = b''):
        if len(node_id) != 32:
            # Handle hex strings if necessary
            if isinstance(node_id, str) and len(node_id) == 64:
                node_id = bytes.fromhex(node_id)
            else:
                raise ValueError("node_id must be 32 bytes raw")
                
        self.msg_type = msg_type
        self.node_id = node_id
        self.payload = payload
        self.hmac = b'\x00' * 32
        
    def serialize(self, hmac_key: bytes) -> bytes:
        """Serializes the packet and computes the HMAC."""
        # Header: Magic(4) + Type(1) + NodeID(32) + PayloadLen(4)
        header = self.MAGIC + struct.pack('!BI', self.msg_type, len(self.payload)) + self.node_id
        # Wait, the spec says: MAGIC (4) + TYPE (1) + NODE_ID (32) + PAYLOAD_LEN (4)
        # Struct pack: B is 1 byte, I is 4 bytes. 
        # Correct order for header:
        header = self.MAGIC + struct.pack('!B', self.msg_type) + self.node_id + struct.pack('!I', len(self.payload))
        
        packet_no_hmac = header + self.payload
        
        # Compute HMAC-SHA256
        h = hmac.new(hmac_key, packet_no_hmac, hashlib.sha256)
        self.hmac = h.digest()
        
        return packet_no_hmac + self.hmac

    @classmethod
    def deserialize(cls, data: bytes, hmac_key: bytes):
        """Deserializes bytes into an ArchipelPacket and verifies HMAC."""
        if len(data) < cls.HEADER_SIZE + cls.FOOTER_SIZE:
            return None, "Packet too short"
            
        magic = data[0:4]
        if magic != cls.MAGIC:
            return None, "Invalid MAGIC"
            
        msg_type = data[4]
        node_id = data[5:37]
        payload_len = struct.unpack('!I', data[37:41])[0]
        
        if len(data) < cls.HEADER_SIZE + payload_len + cls.FOOTER_SIZE:
            return None, "Incomplete payload"
            
        payload = data[cls.HEADER_SIZE:cls.HEADER_SIZE + payload_len]
        received_hmac = data[cls.HEADER_SIZE + payload_len:cls.HEADER_SIZE + payload_len + 32]
        
        # Verify HMAC
        packet_no_hmac = data[:cls.HEADER_SIZE + payload_len]
        h = hmac.new(hmac_key, packet_no_hmac, hashlib.sha256)
        expected_hmac = h.digest()
        
        if not hmac.compare_digest(received_hmac, expected_hmac):
            return None, "HMAC mismatch"
            
        return cls(msg_type, node_id, payload), None

def payload_to_json(payload: bytes) -> dict:
    """Helper to decode binary payload back to dict if it was JSON."""
    try:
        return json.loads(payload.decode('utf-8'))
    except:
        return {}

def json_to_payload(data: dict) -> bytes:
    """Helper to encode dict to binary payload."""
    return json.dumps(data).encode('utf-8')
