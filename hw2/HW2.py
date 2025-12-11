import asyncio
import random
import struct
import socket
import time
import pickle
import os
from typing import Tuple, List, Dict, Any, Optional

CACHE_FILE = "dns_cache.pkl"
LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 5300
ROOT_SERVERS = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]


TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_AAAA = 28
CLASS_IN = 1

QUERY_TIMEOUT = 4.0

class DNSCache:
    def __init__(self, path=CACHE_FILE):
        self.path = path
        self.store = {}
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "rb") as f:
                    self.store = pickle.load(f)
            except Exception as e:
                print("Warning: failed to load cache:", e)
                self.store = {}

    def save(self):
        try:
            with open(self.path, "wb") as f:
                pickle.dump(self.store, f)
        except Exception as e:
            print("Warning: failed to save cache:", e)

    def get(self, name: str, qtype: int):
        key = (name.lower(), qtype)
        now = time.time()
        if key not in self.store:
            return None
        rrs = [rr for rr in self.store[key] if rr["expiry"] > now]
        if rrs:
            return rrs
        else:
            if key in self.store:
                del self.store[key]
                self.save()
            return None

    def put(self, name: str, qtype: int, rrs: List[Dict[str, Any]]):
        key = (name.lower(), qtype)
        self.store[key] = rrs
        self.save()

cache = DNSCache()


def encode_name(name: str) -> bytes:
    if name == "." or name == "":
        return b"\x00"
    parts = name.rstrip(".").split(".")
    out = b""
    for p in parts:
        out += bytes([len(p)]) + p.encode("ascii")
    out += b"\x00"
    return out

def decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    jumped = False
    orig_offset = offset
    while True:
        if offset >= len(data):
            return ("", offset)
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return ("", offset + 1)
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset: offset + length].decode("ascii", errors="ignore"))
        offset += length
    return (".".join(labels), (orig_offset if jumped else offset))

def build_query(qname: str, qtype: int, qid: Optional[int]=None) -> bytes:
    if qid is None:
        qid = random.getrandbits(16)
    flags = 0x0000
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    q = encode_name(qname) + struct.pack("!HH", qtype, CLASS_IN)
    return header + q

def parse_question(data: bytes, offset: int):
    qname, offset = decode_name(data, offset)
    qtype, qclass = struct.unpack_from("!HH", data, offset)
    offset += 4
    return {"qname": qname, "qtype": qtype, "qclass": qclass}, offset

def parse_rr(data: bytes, offset: int):
    name, offset = decode_name(data, offset)
    if offset + 10 > len(data):
        return None, offset
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    rdata = data[offset: offset + rdlength]
    offset += rdlength
    rd = None
    if rtype == TYPE_A and rdlength == 4:
        rd = socket.inet_ntoa(rdata)
    elif rtype == TYPE_AAAA and rdlength == 16:
        rd = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype in (TYPE_NS, TYPE_CNAME):
        rd_name, _ = decode_name(data, offset - rdlength)
        rd = rd_name
    else:
        rd = rdata
    return {"name": name, "type": rtype, "class": rclass, "ttl": ttl, "rdata": rd}, offset

def parse_response(data: bytes):
    if len(data) < 12:
        return None
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, 0)
    offset = 12
    questions = []
    for _ in range(qdcount):
        q, offset = parse_question(data, offset)
        questions.append(q)
    answers = []
    for _ in range(ancount):
        rr, offset = parse_rr(data, offset)
        if rr:
            answers.append(rr)
    authorities = []
    for _ in range(nscount):
        rr, offset = parse_rr(data, offset)
        if rr:
            authorities.append(rr)
    additionals = []
    for _ in range(arcount):
        rr, offset = parse_rr(data, offset)
        if rr:
            additionals.append(rr)
    return {
        "id": id,
        "flags": flags,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals
    }


def udp_query_once(server_ip: str, query_bytes: bytes, use_tcp=False) -> Optional[bytes]:
    try:
        if not use_tcp:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(QUERY_TIMEOUT)
                s.sendto(query_bytes, (server_ip, 53))
                data, _ = s.recvfrom(4096)
                return data
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(QUERY_TIMEOUT)
                s.connect((server_ip, 53))
                length_pref = struct.pack("!H", len(query_bytes))
                s.sendall(length_pref + query_bytes)
                two = s.recv(2)
                if len(two) < 2:
                    return None
                (L,) = struct.unpack("!H", two)
                resp = b""
                while len(resp) < L:
                    chunk = s.recv(L - len(resp))
                    if not chunk:
                        break
                    resp += chunk
                return resp
    except Exception as e:
        return None


def name_has_multiply(name: str) -> Optional[int]:
    labels = name.rstrip(".").split(".")
    for i, lab in enumerate(labels):
        if lab == "multiply":
            prod = 1
            found = False
            j = i - 1
            while j >= 0 and labels[j].isdigit():
                found = True
                prod = (prod * int(labels[j])) % 256
                j -= 1
            if found:
                return prod
            else:
                return 0
    return None

def rr_to_cache_entries(rrs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    now = time.time()
    out = []
    for rr in rrs:
        e = {
            "name": rr["name"].lower(),
            "type": rr["type"],
            "ttl": rr["ttl"],
            "expiry": now + rr["ttl"],
            "rdata": rr["rdata"]
        }
        out.append(e)
    return out

def pick_ip_from_additional(additionals: List[Dict[str, Any]], nsname: str) -> Optional[str]:
    for rr in additionals:
        if rr["name"].lower() == nsname.lower() and rr["type"] == TYPE_A:
            return rr["rdata"]
    return None

def resolve_ns_name_to_ip(nsname: str) -> Optional[str]:
    res = resolve_iterative(nsname, TYPE_A)
    if res:
        for r in res:
            if r["type"] == TYPE_A:
                return r["rdata"]
    return None

def resolve_iterative(qname: str, qtype: int) -> Optional[List[Dict[str, Any]]]:
    qname = qname.rstrip(".")
    mul = name_has_multiply(qname)
    if mul is not None:
        return [{"name": qname, "type": TYPE_A, "ttl": 60, "rdata": f"127.0.0.{mul}"}]

    cached = cache.get(qname, qtype)
    if cached:
        return [{"name": e["name"], "type": e["type"], "ttl": int(e["expiry"] - time.time()), "rdata": e["rdata"]} for e in cached]

    servers = ROOT_SERVERS.copy()
    tried = set()
    for server in servers:
        current_server = server
        while True:
            qbytes = build_query(qname, qtype)
            resp = udp_query_once(current_server, qbytes, use_tcp=False)
            if resp is None:
                break
            parsed = parse_response(resp)
            if parsed is None:
                break
            if parsed["answers"]:
                rrs = parsed["answers"]
                cache_entries = rr_to_cache_entries(rrs)
                cache.put(qname, qtype, cache_entries)
                return rrs
            if parsed["authorities"]:
                candidate_ip = None
                ns_name = None
                for auth in parsed["authorities"]:
                    if auth["type"] == TYPE_NS:
                        ns_name = auth["rdata"]
                        ip = pick_ip_from_additional(parsed["additionals"], ns_name)
                        if ip:
                            candidate_ip = ip
                            break
                if candidate_ip is None and ns_name:
                    ip = resolve_ns_name_to_ip(ns_name)
                    if ip:
                        candidate_ip = ip
                if candidate_ip:
                    if (current_server, candidate_ip) in tried:
                        break
                    tried.add((current_server, candidate_ip))
                    current_server = candidate_ip
                    continue
                else:
                    break
            else:
                break
    return None


def build_response_for_client(qbytes: bytes, client_qid: int, qname: str, qtype: int, answers: Optional[List[Dict[str, Any]]]) -> bytes:
    if answers is None:
        flags = 0x8000 | 0x0002  # QR=1, RCODE=2
        header = struct.pack("!HHHHHH", client_qid, flags, 1, 0, 0, 0)
        body = encode_name(qname) + struct.pack("!HH", qtype, CLASS_IN)
        return header + body
    flags = 0x8000 | 0x0080  # QR=1, RA=1
    header = struct.pack("!HHHHHH", client_qid, flags, 1, len(answers), 0, 0)
    qpart = encode_name(qname) + struct.pack("!HH", qtype, CLASS_IN)
    answers_bytes = b""
    for rr in answers:
        answers_bytes += encode_name(rr["name"])
        answers_bytes += struct.pack("!HHI", rr["type"], CLASS_IN, rr["ttl"])
        if rr["type"] == TYPE_A:
            rdata = socket.inet_aton(rr["rdata"])
        elif rr["type"] == TYPE_AAAA:
            rdata = socket.inet_pton(socket.AF_INET6, rr["rdata"])
        elif rr["type"] in (TYPE_NS, TYPE_CNAME):
            rdata = encode_name(rr["rdata"])
        else:
            if isinstance(rr["rdata"], bytes):
                rdata = rr["rdata"]
            else:
                rdata = str(rr["rdata"]).encode("utf-8")
        answers_bytes += struct.pack("!H", len(rdata))
        answers_bytes += rdata
    return header + qpart + answers_bytes


class DNSDatagramProtocol:
    def __init__(self, loop):
        self.loop = loop

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.loop.create_task(self.handle_query_udp(data, addr))

    async def handle_query_udp(self, data: bytes, addr):
        if len(data) < 12:
            return
        client_qid = struct.unpack_from("!H", data, 0)[0]
        parsed = parse_response(data)  # parse header+questions
        if not parsed or not parsed["questions"]:
            return
        q = parsed["questions"][0]
        qname = q["qname"]
        qtype = q["qtype"]
        answers = resolve_iterative(qname, qtype)
        resp_bytes = build_response_for_client(data, client_qid, qname, qtype, answers)
        self.transport.sendto(resp_bytes, addr)

class TCPHandler(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop
        self.buffer = b""
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        self.buffer += data
        while True:
            if len(self.buffer) < 2:
                return
            L = struct.unpack_from("!H", self.buffer, 0)[0]
            if len(self.buffer) < 2 + L:
                return
            msg = self.buffer[2:2+L]
            self.buffer = self.buffer[2+L:]
            self.loop.create_task(self.handle_query_tcp(msg))

    async def handle_query_tcp(self, data: bytes):
        if len(data) < 12:
            return
        client_qid = struct.unpack_from("!H", data, 0)[0]
        parsed = parse_response(data)
        if not parsed or not parsed["questions"]:
            return
        q = parsed["questions"][0]
        qname = q["qname"]
        qtype = q["qtype"]
        answers = resolve_iterative(qname, qtype)
        resp = build_response_for_client(data, client_qid, qname, qtype, answers)
        self.transport.write(struct.pack("!H", len(resp)) + resp)

    def connection_lost(self, exc):
        pass

async def main():
    loop = asyncio.get_running_loop()
    print(f"Starting iterative DNS server on {LISTEN_ADDR}:{LISTEN_PORT} (UDP & TCP)")
    listen = await loop.create_datagram_endpoint(lambda: DNSDatagramProtocol(loop),
                                                local_addr=(LISTEN_ADDR, LISTEN_PORT))
    server = await loop.create_server(lambda: TCPHandler(loop), LISTEN_ADDR, LISTEN_PORT)
    try:
        await server.serve_forever()
    finally:
        listen.close()
        server.close()
        await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shutting down.")
