# UDP — Study Notes

Companion to [tcp-notes.md](tcp-notes.md).
Interactive version: [UDP on the Wire](udp-on-the-wire.html) — side-by-side TCP/UDP packet race,
live-decoded DNS query, working checksum lab.

Checked against RFC 768 (the protocol, unrevised since 1980), RFC 1122 (host requirements),
RFC 8085 (usage guidelines), RFC 6891 (EDNS0), RFC 9000 (QUIC), RFC 2827 / BCP 38 (ingress
filtering), US-CERT TA14-013A (amplification factors).

---

## 1. What UDP actually is

A thin shim over IP that adds **exactly two things**:

1. **Ports** — 16 bits each way, so the kernel can demultiplex to the right socket.
2. **A checksum** — optional over IPv4, mandatory over IPv6.

That is the complete feature list. RFC 768 is three pages long — not a summary, the whole spec.

> **The reframe:** UDP is not "TCP with the safety off." It is *raw IP you're allowed to address
> to a program*. Whatever guarantees you need, you build on top — and only the ones you need.
> That is why QUIC is built on UDP rather than on TCP.

### What's absent, and what it costs

| Property | TCP | UDP | Consequence |
|---|---|---|---|
| Connection setup | 3-way handshake | none | UDP's first byte leaves immediately — a full RTT saved |
| Delivery guarantee | yes, retransmits | none | a lost datagram is gone silently and permanently |
| Ordering | strict | none | datagram 5 can arrive before datagram 4 |
| Duplicate suppression | yes | none | the same datagram can be delivered twice |
| Flow control | sliding window | none | overrun the receiver and the kernel just drops |
| Congestion control | cwnd, AIMD | none | your app can melt a link and never notice |
| **Message boundaries** | destroyed | **preserved** | the one thing UDP does *better* |
| Connection state | ~1–4 KB/conn | none | one socket can serve millions of peers |
| Header size | 20–60 B | **8 B** | 29% vs 50% overhead on a 20-byte voice frame |
| **Multicast / broadcast** | impossible | **supported** | one send, many receivers |

---

## 2. The header — 8 bytes, four fields

```
|<---------------------------- 32 bits ---------------------------->|
+----------------------------------+----------------------------------+
|         Source Port  16          |      Destination Port  16        |
+----------------------------------+----------------------------------+
|            Length  16            |         Checksum  16             |
+----------------------------------+----------------------------------+
|                    payload — 0 to 65,507 bytes                      |
+---------------------------------------------------------------------+
```

No sequence number, no ack number, no flags, no window, no options, no data offset.
The header is a fixed 8 bytes and never any other size — which is *why* it can't offer reliability.
There is nowhere to put the state.

- **Source port** may legally be **0**, meaning "no reply expected." Rare, but it's in the spec and
  it tells you the mindset: a UDP send is not a request, it's an announcement.
- **Length** counts header + payload, minimum 8. It is entirely **redundant** with the IP total
  length field — one of the few places the stack transmits the same number twice.

### A real DNS query, decoded

```
0000  D4 31 00 35 00 25 C3 8E                      <- the whole UDP header
      └sport┘ └dport┘ └len ┘ └cksum┘
      54321   53      37     computed

0008  AB CD 01 00 00 01 00 00     DNS: id, flags(RD), qdcount=1, ancount=0
0010  00 00 00 00 07 65 78 61     nscount=0, arcount=0, then QNAME: 07 'exa
0018  6D 70 6C 65 03 63 6F 6D     mple' 03 'com'
0020  00 00 01 00 01              terminator, QTYPE=1 (A), QCLASS=1 (IN)
```

There are **no dots on the wire** — the dots in "example.com" are the length prefixes `07` and `03`.
That length byte is why a DNS label can't exceed 63 characters.

---

## 3. Message boundaries — the thing UDP does better

TCP is a **byte stream**: writes get merged and split, boundaries are destroyed.
UDP is a **datagram** protocol: one `send()` = one datagram = one `recv()`, whole.

```
sends:  [700 B] [400 B] [900 B]
UDP  →  recv 700 · recv 400 · recv 900     3 → 3, exact
TCP  →  recv 1460 · recv 540               3 → 2, wrong
```

**All or nothing.** There is no such thing as receiving half a UDP datagram. If any IP fragment is
lost, the whole datagram is discarded and `recvfrom()` never sees it.

> **Gotcha:** because a datagram is atomic, your receive buffer must fit the whole thing.
> `recvfrom()` with a 512-byte buffer when a 900-byte datagram arrives gives you 512 bytes and
> **silently discards the other 388** — they are not queued for the next read. Size the buffer to
> your protocol's maximum, or pass `MSG_TRUNC` to detect the truncation.

---

## 4. Checksum — two twists

Same ones'-complement algorithm as TCP, same end-around carry. Covers:

1. A **12-byte pseudo-header** — src IP (4) + dst IP (4) + zero (1) + **protocol 17** (1) + UDP length (2). Never transmitted.
2. The **8-byte UDP header**, with the checksum field zeroed.
3. The **payload**, zero-padded to an even length (pad not sent).

Receiver sums everything *including* the checksum → a valid datagram sums to `0xFFFF`.

**Twist 1 — zero means "I didn't bother."** Over IPv4 the checksum is *optional*: send `0x0000` and
the receiver skips verification. Over **IPv6 it is mandatory**, because IPv6 removed the IP header
checksum — remove it at both layers and one flipped bit in a destination address delivers your
datagram to a stranger with nothing to catch it.

**Twist 2 — the 0xFFFF substitution.** What if the real checksum computes to `0x0000`? It would be
indistinguishable from "not computed." RFC 768's answer: **transmit `0xFFFF` instead.** This works
because ones'-complement arithmetic has two representations of zero — `0x0000` (+0) and `0xFFFF`
(−0) — that are numerically equal. One is reserved as a sentinel, the other carries the value.

---

## 5. Size — 65,507 in theory, ~1,200 in practice

```
65,535   IPv4 total length maximum
  − 20   IPv4 header
  −  8   UDP header
─────────
65,507   largest UDP payload over IPv4      (65,527 over IPv6)
```

Never go near it. Anything over `path MTU − 28` gets **fragmented by IP**:

- **One lost fragment destroys the entire datagram.** At 1% packet loss, an *n*-fragment datagram
  survives with probability 0.99ⁿ — 99% for 1, 97% for 3, 95% for 5. And loss is total.
- Many firewalls and load balancers **drop non-initial fragments outright**, because only the first
  fragment carries the UDP header with the port numbers a stateless filter needs.

> **Rule: keep UDP payloads under ~1,200 bytes.** That fits inside essentially every path MTU
> including tunnels and VPNs. It is what QUIC requires (1,200 B minimum datagram), what RFC 8085
> advises, and where DNS converged. If your data doesn't fit: split it yourself with per-piece
> recovery, or use TCP.

**DNS history:** classic cap was **512 bytes** (RFC 791 guarantees 576-byte reassembly). Over-size
responses set the `TC` bit → retry over TCP. **EDNS0** raised it to ~4096, which became a
fragmentation-attack vector. *DNS Flag Day 2020* swung it back to **~1232 bytes**.

---

## 6. No brakes

**Overrun the receiver** → socket buffer fills → the kernel *drops and increments a counter*.
The sender sees a successful `send()`. Nobody is told.

```bash
netstat -su               # "packet receive errors" = datagrams thrown away
ss -ulnm                  # rb=<n> is SO_RCVBUF, the drop threshold
nstat -az | grep -i udp   # UdpInErrors, UdpRcvbufErrors, UdpNoPorts
```
Fix: raise `SO_RCVBUF` (capped by `net.core.rmem_max`), never do work on the `recvfrom()` thread,
and use `recvmmsg()` for high rates.

**Overrun the network** → no cwnd, no backoff. Loss-based TCP flows on the same link *do* back off,
so your traffic crowds them out entirely.

> **RFC 8085 is an obligation, not etiquette.** An application sending more than a few datagrams per
> RTT **should** implement congestion control, no more aggressive than TCP would be — and in IETF
> language "should" means "do it unless you can defend not doing it". Getting this wrong
> doesn't fail in testing — it works on your LAN and degrades the network for everyone in production.

---

## 7. `connect()` on a UDP socket

It sends no packets and establishes nothing. It's still one of the most useful calls available:

1. Use `send()`/`recv()` instead of `sendto()`/`recvfrom()`.
2. The kernel **filters inbound datagrams** to that peer only.
3. **You start receiving ICMP errors.**

Point 3 is the big one. On an *unconnected* socket the kernel discards ICMP errors — it can't know
which peer they refer to — so sending to a dead port "succeeds" and you learn nothing. On a
*connected* socket, that ICMP port-unreachable surfaces as **`ECONNREFUSED`**.

The difference between "hangs until timeout" and "fails instantly with a clear error" is one
`connect()` call that transmits nothing. Undo with `AF_UNSPEC`. Servers stay unconnected (one socket,
every client — that's the scaling win); clients talking to one server should almost always connect.

---

## 8. Who uses UDP, and what they rebuilt

| Protocol | Port | Why UDP | Rebuilt on top |
|---|---|---|---|
| **DNS** | 53 | one small request/reply; a handshake would triple latency | timeout+retry, 16-bit transaction ID, TCP fallback on `TC` |
| **QUIC** / HTTP3 | 443 | needed per-stream loss recovery TCP can't give; deployable in userspace | *everything* — streams, ACKs, congestion control, TLS 1.3, migration, 0-RTT |
| **DHCP** | 67/68 | client has no IP yet, and must broadcast | retry with backoff, transaction IDs |
| **NTP** | 123 | needs *minimum* path delay; TCP's buffering poisons a clock | nothing — a lost sample is skipped |
| **RTP** / WebRTC | dynamic | a late voice packet is worthless; retransmit = gap *and* stall | sequence numbers, timestamps, jitter buffer, RTCP, FEC, selective NACK |
| **Games** | varies | state is absolute — position at t=100 makes t=99 irrelevant | sequence numbers, delta compression, client prediction, redundant state |
| **WireGuard** | 51820 | TCP-in-TCP causes "TCP meltdown" — two retransmit timers fighting | own handshake + replay protection |
| **syslog** | 514 | logging must never block the app it instruments | nothing, deliberately (RFC 5425 = TLS/TCP variant) |
| **SNMP** | 161/162 | polling thousands of devices; must work when the network is sick | request IDs, timeout+retry |
| **mDNS / SSDP** | 5353 / 1900 | discovery is one-to-many; TCP can't multicast | repetition, randomised delays |
| **TFTP** | 69 | fits in a boot ROM | stop-and-wait with block numbers — reliability rebuilt badly, on purpose |

**The pattern:** they didn't want *less* reliability — several rebuilt more machinery than TCP has.
They needed a **different** reliability: per-stream instead of per-connection, bounded-latency
instead of guaranteed, or none at all for data that expires faster than it can be repaired.
TCP offers exactly one policy and it isn't configurable.

---

## 9. Multicast & broadcast — TCP can't go here

TCP is definitionally point-to-point; its ack mechanism is meaningless with a thousand receivers.

- **Broadcast** (UDP only) — `255.255.255.255` or subnet broadcast, local link only, routers don't
  forward. How DHCP finds a server before it has an address. IPv6 removed it entirely.
- **Multicast** (UDP only) — group addresses `224.0.0.0/4` (v4) / `ff00::/8` (v6), receivers opt in
  via IGMP/MLD. Sender transmits **one** packet; the network duplicates only where paths diverge.

Known groups: `224.0.0.1` all hosts · `224.0.0.251` mDNS/Bonjour · `239.255.255.250` SSDP/UPnP.

Multicast is indispensable inside a datacenter or carrier network (market data, IPTV) and
**essentially undeliverable across the public internet** — it needs inter-domain router agreement
that never materialised.

---

## 10. Amplification — the dark side

Two UDP properties combine into the most effective DDoS technique in existence:

1. **No handshake = the source address is never verified.** TCP's handshake incidentally proves the
   client can receive at the address it claims. UDP has no such step, so an attacker puts the
   *victim's* address in the source field and the server replies to the victim.
2. **Some services answer a tiny question with an enormous reply.**

| Protocol | Amplification factor |
|---|---|
| **memcached** | up to **51,000×** |
| NTP (`monlist`) | 556.9× |
| CharGen | 358.8× |
| RIPv1 | 131.2× |
| CLDAP | 56× |
| DNS | 28–54× |
| SSDP | 30.8× |
| SNMPv2 | 6.3× |
| NetBIOS | 3.8× |

The 2018 memcached attacks peaked at **1.35 Tbit/s against GitHub** — the largest DDoS recorded at the
time, generated from a tiny fraction of that bandwidth. Cause: tens of thousands of memcached servers exposed on UDP
port 11211 by default, with no authentication.

**If you run a network:** implement **BCP 38** (RFC 2827) ingress filtering — drop outbound packets
whose source doesn't belong to you. Universal adoption would eliminate this entire attack class.

**If you run a UDP service:**
- Never let the response be much larger than the request. That's the whole game.
- Validate the source address before expensive work — exactly what QUIC's *address validation* does
  (unvalidated clients get at most 3× what they sent; a Retry token forces a round trip). A
  handshake, reinvented because UDP lacks one.
- Rate-limit per source (DNS Response Rate Limiting).
- Don't expose it. memcached disabled UDP by default in 1.5.6 — after the fact.
- **Run `nmap -sU` against your own public ranges.** Fastest security audit in networking.

---

## 11. "We'll just add reliability to UDP"

The full bill for every-message-delivered-in-order-exactly-once:

| Mechanism | Difficulty |
|---|---|
| Sequence numbers, ACKs | easy |
| Retransmission timer, RTT estimation, reordering buffer, flow control | medium |
| **Congestion control** | **hard** |
| Path MTU discovery, connection identity, encryption & auth | hard |
| Keepalive / NAT traversal (mappings die in 30 s–2 min), address validation | medium |

The first group is a weekend. **Congestion control is not** — it took the field thirty years, from
the congestion collapse of 1986 through Tahoe, Reno and CUBIC to BBR in 2016, to get it right. Getting it
wrong doesn't produce a bug you catch in testing.

> **Recommendation:** if you need full reliability over UDP, **use QUIC** (RFC 9000). Deployed at
> internet scale, attacked and patched for years, mature libraries everywhere (`quic-go`, `quinn`,
> `msquic`, `aioquic`, `lsquic`). You get every row above plus TLS 1.3, independent streams without
> head-of-line blocking, and connection migration.
>
> Roll your own only for **partial** reliability — the case QUIC doesn't cover and TCP can't express.
> Real-time media is the honest example: retransmit the keyframe, drop the stale audio packet, never
> stall for either.

---

## 12. Choosing

Not "do I need reliability?" (everyone says yes) but **"what is a late message worth to me?"**

1. **Is stale data worse than no data?** Video frame, player position, clock sample → retransmission
   is damage, not a feature. **UDP.**
2. **Must one lost message block the others?** Independent streams on one link → TCP stalls all of
   them. **QUIC over UDP.**
3. **One small request, one small reply?** The handshake would dominate. **UDP** + your own retry.
4. **One-to-many?** **UDP.** TCP cannot.
5. **No IP address yet?** **UDP.**
6. **Anything else** — bulk transfer, API call, database. **TCP.** Use the 30 years of tuning.

**Two myths:**
- *"UDP is faster."* Not in throughput — on a healthy path a single TCP flow beats naive UDP, because
  congestion control keeps it out of full queues. UDP wins on **latency**: no setup RTT, no
  head-of-line blocking. Different words, and the difference matters.
- *"UDP is for unimportant data."* It carries DNS, every device's boot process, the world's time sync,
  and a rising share of all web traffic via HTTP/3. It's the protocol for data whose **value decays
  faster than the network can repair it** — or whose recovery you want to control yourself.

---

## 13. Seeing it

```bash
# terminal 1                        # terminal 2
nc -u -l 9999                       echo hi | nc -u -w1 127.0.0.1 9999

# send to a dead port — note that it "succeeds" (ICMP error discarded)
echo hi | nc -u -w1 127.0.0.1 9998

# a real DNS query, 29 bytes out / 45 back, one RTT, zero setup
sudo tcpdump -i any -n -v 'udp port 53'
dig +notcp @1.1.1.1 example.com A
dig +tcp   @1.1.1.1 example.com A     # compare the packet count

ss -ulnp                              # listening UDP sockets + processes
ss -ulnm                              # + socket memory; rb = SO_RCVBUF
netstat -su                           # receive errors = dropped datagrams
nstat -az | grep -i reasm             # IpReasmFails = fragmentation losses
```

Wireshark: `udp.length > 1400` (heading for fragmentation) · `udp.checksum == 0` (skipped) ·
`ip.flags.mf == 1 || ip.frag_offset > 0` (fragments) · `icmp.type == 3 && icmp.code == 3`
(port unreachable) · `dns.flags.truncated == 1` (forced a TCP retry) · `quic`.

---

## 14. Triage

| Symptom | Cause | Check |
|---|---|---|
| Datagrams vanish under load only | receive buffer overrun | `netstat -su`, raise `SO_RCVBUF` |
| Small messages fine, large ones never arrive | fragmentation | `nstat \| grep Reasm`, stay under 1200 B |
| Client hangs instead of failing fast | unconnected socket discards ICMP | call `connect()` |
| Only part of a message arrives | recv buffer < datagram | size to max, or `MSG_TRUNC` |
| Works, dies after ~30 s idle | NAT dropped the mapping | keepalive every 15–25 s |
| Your traffic starves TCP on the link | no congestion control | rate-limit, or move to QUIC |
| Abuse complaints about your server | you're an amplifier | `nmap -sU` your own ranges |
| DNS works for some names, not others | large responses fragmenting/truncated | `dig +bufsize=1232`, `dig +tcp` |

---

## Reference card

- **Header** `8 bytes`, always — sport, dport, length, checksum, 16 bits each. No options, no flags.
- **Sizes** max payload `65,507` (IPv4) / `65,527` (IPv6). **Stay under ~1,200 B.** Length ≥ 8.
- **Checksum** optional on IPv4 (`0x0000` = skipped), **mandatory on IPv6**. Real zero → send `0xFFFF`.
  12-byte pseudo-header, protocol `17`.
- **Kept:** message boundaries, all-or-nothing delivery, integrity (if enabled).
  **Absent:** delivery, ordering, dedup, flow control, congestion control.
- **Ports** `53` DNS · `67/68` DHCP · `69` TFTP · `123` NTP · `161` SNMP · `443` QUIC/HTTP3 ·
  `514` syslog · `1900` SSDP · `5353` mDNS · `51820` WireGuard
- **Obligations** RFC 8085: congestion control above a few datagrams/RTT · response ≤ request ·
  validate source addresses before expensive work.
