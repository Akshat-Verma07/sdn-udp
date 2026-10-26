"""
protocol.py - Shared wire protocol for the Reliable UDP File Transfer (RUFT).

UDP gives us no ordering, no delivery guarantee and no duplicate protection,
so we build those ourselves on top of it.  Every datagram we send starts with
the same fixed header, followed by an optional payload:

     0       1       2               6              10      12
     +-------+-------+---------------+---------------+-------+----------...
     | magic | type  |   session id  |  seq / value  |  len  |  payload
     +-------+-------+---------------+---------------+-------+----------...
       1 B     1 B        4 B             4 B          2 B     0..CHUNK B
                                                     (header = 12 bytes)
     ... payload ...+-----------+
                    |  CRC-32   |   <- covers header + payload (4 B trailer)
                    +-----------+

Packet types
------------
START : sender -> receiver.  payload = JSON {filename, size, chunks, chunk_size}
        'seq' is unused (0).  Starts a transfer session.
START_ACK : receiver -> sender.  Confirms the START was received.
DATA  : sender -> receiver.  'seq' = chunk index (0-based), payload = file bytes.
ACK   : receiver -> sender.  'seq' = chunk index being acknowledged
        (SELECTIVE ack: each DATA packet gets its own ACK, so the sender knows
        exactly which chunks arrived even when they arrive out of order).
FIN   : sender -> receiver.  payload = SHA-256 hex digest of the whole file.
FIN_ACK : receiver -> sender.  'seq' = 1 if the SHA-256 matched, 0 if not.
        (This is our end-to-end integrity verification.)

Why a CRC on every packet *and* a SHA-256 on the whole file?
  * CRC-32 catches bit corruption in a single datagram immediately, so a
    corrupted packet is dropped and later retransmitted (as if it were lost).
  * SHA-256 is the final end-to-end check that the reassembled file is
    byte-identical to the original.
"""

import json
import struct
import zlib

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAGIC = 0xA7                 # Quick sanity byte; non-RUFT traffic is ignored.

# Packet type codes
T_START = 1
T_START_ACK = 2
T_DATA = 3
T_ACK = 4
T_FIN = 5
T_FIN_ACK = 6

TYPE_NAMES = {
    T_START: "START", T_START_ACK: "START_ACK", T_DATA: "DATA",
    T_ACK: "ACK", T_FIN: "FIN", T_FIN_ACK: "FIN_ACK",
}

# Header layout: magic(B) type(B) session(I) seq(I) length(H)  -> network order
HEADER_FMT = "!BBIIH"
HEADER_LEN = struct.calcsize(HEADER_FMT)      # 12 bytes
CRC_LEN = 4                                    # CRC-32 trailer

# Payload size per DATA packet.  1024 B keeps the whole datagram well under the
# typical 1500 B Ethernet MTU (1024 + 12 + 4 + 8 UDP + 20 IP = 1068 B), so IP
# fragmentation never happens inside Mininet.
CHUNK_SIZE = 1024
MAX_PACKET = HEADER_LEN + CHUNK_SIZE + CRC_LEN + 512   # recv buffer headroom

DEFAULT_PORT = 5005


class PacketError(Exception):
    """Raised when a received datagram is malformed or fails the CRC check."""


# ---------------------------------------------------------------------------
# Encoding / decoding
# ---------------------------------------------------------------------------
def build_packet(ptype: int, session: int, seq: int = 0,
                 payload: bytes = b"") -> bytes:
    """Serialize one packet: header + payload + CRC-32 trailer."""
    header = struct.pack(HEADER_FMT, MAGIC, ptype, session, seq, len(payload))
    body = header + payload
    # CRC is computed over header+payload, masked to an unsigned 32-bit value.
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return body + struct.pack("!I", crc)


def parse_packet(data: bytes):
    """
    Validate and deserialize a datagram.

    Returns (ptype, session, seq, payload).
    Raises PacketError if the packet is too short, has the wrong magic byte,
    an inconsistent length field, or a CRC mismatch (i.e. it was corrupted in
    transit).  Callers simply DROP such packets: the reliability layer will
    recover them through timeout + retransmission.
    """
    if len(data) < HEADER_LEN + CRC_LEN:
        raise PacketError("packet too short")

    body, crc_bytes = data[:-CRC_LEN], data[-CRC_LEN:]
    (crc_recv,) = struct.unpack("!I", crc_bytes)
    if (zlib.crc32(body) & 0xFFFFFFFF) != crc_recv:
        raise PacketError("CRC mismatch (corrupted packet)")

    magic, ptype, session, seq, length = struct.unpack(
        HEADER_FMT, body[:HEADER_LEN])
    if magic != MAGIC:
        raise PacketError("bad magic byte")
    payload = body[HEADER_LEN:]
    if length != len(payload):
        raise PacketError("length field does not match payload size")
    if ptype not in TYPE_NAMES:
        raise PacketError("unknown packet type %d" % ptype)
    return ptype, session, seq, payload


# ---------------------------------------------------------------------------
# Helpers for the control-packet payloads
# ---------------------------------------------------------------------------
def encode_start(filename: str, size: int, chunks: int) -> bytes:
    """JSON payload for START: what file is coming and how big it is."""
    return json.dumps({
        "filename": filename,
        "size": size,
        "chunks": chunks,
        "chunk_size": CHUNK_SIZE,
    }).encode()


def decode_start(payload: bytes) -> dict:
    try:
        meta = json.loads(payload.decode())
        # Basic validation so a garbage START cannot crash the receiver.
        for key in ("filename", "size", "chunks", "chunk_size"):
            if key not in meta:
                raise ValueError("missing field " + key)
        return meta
    except (ValueError, UnicodeDecodeError) as exc:
        raise PacketError("bad START payload: %s" % exc)
