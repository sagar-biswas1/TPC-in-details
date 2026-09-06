# TCP — Study Notes (corrected & expanded)

Source: original handwritten notes + [TCP on the Wire](https://claude.ai/code/artifact/a3e31fbb-078f-46c8-a7bd-cd856c37274c)
(interactive version — packet simulator, header explorer, state machine).

Checked against RFC 9293 (core, 2022 — obsoletes RFC 793), RFC 7323 (window scale, timestamps),
RFC 5681 (congestion control), RFC 6298 (RTO), RFC 2018 (SACK), RFC 6528 (ISN),
RFC 6928 (initial window 10), RFC 8311 (retired the NS bit).

---

## 0. The corrections, up front

| # | Original note | Correction |
|---|---|---|
| 1 | Final ACK: `S-3000 → D-50123` | **`S-50123 → D-3000`.** The client sends segment 3, so ports flip back. seq=1001 / ack=2001 were right. |
| 2 | `Data offset(4) \| reserved(3) \| Flag \| Window(16)` | **Data Offset (4) · Reserved (4) · Control Bits (8) · Window (16).** The 3-bit version was RFC 3540's layout; RFC 8311 made the NS bit historic in 2018. |
| 3 | `16 bit = 65535` | 16 bits = **65,536 values** (0–65535). 65,535 *usable* ports because port 0 is reserved. |
| 4 | Flags: `SYN, ACK, FIN, RST, PSH, PSH, URG, ECE, CWR, NS` | PSH listed twice. Eight live bits in header order: **CWR ECE URG ACK PSH RST SYN FIN**. NS is historic. |
| 5 | "The destination port will say the window size" | The window belongs to neither port. **Every segment carries its own sender's receive window**, both directions, continuously. |
| 6 | "Source can send that much data without ACK" | Right for flow control only. Real cap is **`min(rwnd, cwnd)`** — and **cwnd has no header field at all**. |

Nuances rather than errors:

- **"App layer doesn't know the layers below"** — true as abstraction, but it leaks: `TCP_NODELAY`,
  `SO_RCVBUF`, and a blocking `send()` when the peer's window closes are all TCP showing through.
- **"Four steps to close"** — correct, but the middle ACK and FIN are usually coalesced into one
  `FIN, ACK`, making it three segments in most real traces.
- **"Chrome doesn't use a port"** — it doesn't *listen* on one. It still gets an ephemeral *source*
  port for every connection; the four-tuple requires it.
- **"Random 32-bit sequence number"** — unpredictable, not random. RFC 6528: a 4 µs timer plus a
  keyed hash of the four-tuple.
- **"Window is 16 bits max"** — the *field* is. The *window* reaches 1 GiB via Window Scale.

Correct as written: TCP = Transmission Control Protocol · three-way handshake · all port ranges and
port numbers · data offset 4 bits, min 5, max 15, header 20–60 bytes · ack=0 in a bare SYN ·
ones'-complement checksum · options + padding · the whole HTTP keep-alive analysis.

---

## 1. The idea everything hangs on

**TCP is a stream of bytes, not a stream of messages.**

Every byte in each direction has its own 32-bit number. A segment is just a claim:
*"here are bytes 4381 through 5840."*

Consequence: **`send()` boundaries do not survive.** Three sends of 700 / 400 / 900 bytes become two
segments of 1460 / 540, and the receiver's `recv()` returns 1460 then 540. Not one original boundary
survived. Every protocol on top of TCP re-invents framing — HTTP uses `Content-Length` or chunked
encoding, gRPC prefixes a 5-byte length, Redis uses `\r\n`.

The two arithmetic rules:

```
next_seq = seq + len(payload)   (+1 if SYN or FIN is set)
ack      = the next byte I expect  →  "I have everything below this"
```

SYN and FIN carry no data but each **consumes one sequence number** — a phantom byte. That is *why*
the handshake acknowledges ISN+1.

---

## 2. Where TCP sits

| Layer | Unit | Addressing | Adds |
|---|---|---|---|
| Application (L7) | Message | URL, hostname | — |
| Transport (L4) — TCP | **Segment** | Port, 16 bit | 20–60 B |
| Transport (L4) — UDP | Datagram | Port, 16 bit | 8 B |
| Internet (L3) — IPv4 | Packet | IP, 32 bit | 20–60 B |
| Link (L2) — Ethernet | Frame | MAC, 48 bit | 14 B + 4 B |

Ethernet MTU 1500 − 20 (IP) − 20 (TCP) = **MSS 1460**. IPv6 → 1440 (40-byte header).

---

## 3. The header

```
|<---------------------------- 32 bits ---------------------------->|
+----------------------------------+----------------------------------+
|          Source Port  16         |       Destination Port  16       |
+----------------------------------+----------------------------------+
|                      Sequence Number  32                            |
+---------------------------------------------------------------------+
|                   Acknowledgment Number  32                         |
+--------+--------+-----------------+----------------------------------+
| Doff 4 | Rsvd 4 | Control Bits 8  |            Window  16            |
+--------+--------+-----------------+----------------------------------+
|           Checksum  16           |        Urgent Pointer  16        |
+----------------------------------+----------------------------------+
|                  Options + Padding   0 – 320 bits                   |
+---------------------------------------------------------------------+
```

- **Data Offset** counts **32-bit words**, not bytes. Min 5 (20 B, no options), max 15 (60 B).
  That leaves **40 bytes for options** — a modern SYN already spends 20 on MSS, SACK-permitted,
  Timestamps and Window Scale.
- **Window** must be multiplied by `2^S` where S is the scale from the handshake.
  `win 502` with `wscale 7` = **64,256 bytes**, not 502. Most common trace misreading.
- **Urgent Pointer** is effectively dead — RFC 6093 advises against using it.
- There is **no IP address field**. TCP borrows addresses from IP, which is why the checksum has to
  pull them back in via a pseudo-header.

### Control bits (MSB → LSB)

| Bit | Flag | Hex | Meaning |
|---|---|---|---|
| 7 | CWR | 0x80 | congestion window reduced (ECN) |
| 6 | ECE | 0x40 | ECN echo — a router marked congestion |
| 5 | URG | 0x20 | urgent pointer valid (dead) |
| 4 | ACK | 0x10 | ack field valid — set on every segment after the first SYN |
| 3 | PSH | 0x08 | deliver to the app now, don't buffer |
| 2 | RST | 0x04 | abort immediately |
| 1 | SYN | 0x02 | synchronise — consumes 1 seq |
| 0 | FIN | 0x01 | no more data from me — consumes 1 seq |

`NS` is **historic** (RFC 8311, 2018) — its bit returned to Reserved.

Common combos: `SYN` · `SYN,ACK` · `ACK` · `PSH,ACK` · `FIN,ACK` · `RST` / `RST,ACK`.
Everything else is essentially a scanner or a bug.

---

## 4. Ports

| Range | Name | Notes |
|---|---|---|
| 0–1023 | Well-known | needs root on Unix |
| 1024–49151 | Registered | any user may bind |
| 49152–65535 | Dynamic / ephemeral | IANA recommendation |

Real OS ephemeral defaults: **Linux 32768–60999** (`net.ipv4.ip_local_port_range`),
Windows & macOS 49152–65535.

22 SSH · 23 Telnet · 25 SMTP · 53 DNS · 80 HTTP · 443 HTTPS · 1433 MSSQL · 3306 MySQL ·
5432 Postgres · 6379 Redis · 9092 Kafka · 27017 Mongo

**A connection is a four-tuple:** `(src IP, src port) ⟷ (dst IP, dst port)`. Change any one and it is
a different connection with its own sequence space, window and state machine.

> Practical: a proxy opening connections to one upstream `IP:port` can only vary the source port, so
> it caps near ~28,000 concurrent on Linux minus everything in TIME_WAIT. That is the real cause of
> `EADDRNOTAVAIL`. Fix with pooling and keep-alive, not by widening the range.

---

## 5. Opening

```
1.  SYN       src 50123 → dst 3000    seq=1000  ack=—
2.  SYN, ACK  src 3000  → dst 50123   seq=2000  ack=1001
3.  ACK       src 50123 → dst 3000    seq=1001  ack=2001   ← ports flip back
```

Three is the provable minimum: each side's ISN must be both **sent** and **confirmed**, and segment 2
does both jobs at once.

**ISN (RFC 6528):** `ISN = M + F(localIP, localPort, remoteIP, remotePort, secret)` where M is a 4 µs
timer and F is a keyed hash. The timer keeps old delayed segments from being mistaken for new ones;
the hash makes it unguessable from off-path.

**Two server queues:** the SYN queue (half-open, SYN-RECEIVED, `tcp_max_syn_backlog`) and the accept
queue (established, waiting for `accept()`, `listen(fd, backlog)`). A full accept queue = your app is
too slow. A full SYN queue = half-open pileup → **SYN cookies** (`tcp_syncookies=1`) encode the state
into the ISN so no memory is allocated per half-open connection.

---

## 6. Moving data

```
in flight ≤ min( rwnd , cwnd )

rwnd — receive window : "how much can you buffer?"   flow control,      in the header
cwnd — congestion win : "how much can the net carry?" congestion control, NOT in the header
```

- **Window scale (RFC 7323):** shift count in the SYN, window × 2^S, S ≤ 14 → up to 1 GiB.
  Needed because BDP on 1 Gbit/s × 100 ms = 12.5 MB, and a 64 KB window would use 0.5% of it.
  **The SYN's own window field is never scaled** — the option isn't agreed yet.
- **Zero window** → sender stalls → **persist timer** sends a 1-byte **window probe**, because the
  ACK that would re-open the window is itself not retransmitted.
- **Silly window syndrome** — defended by Clark's rule (receiver) and Nagle (sender).

### Nagle × delayed ACK — the 40 ms stall

- **Nagle (sender):** don't send a small segment while data is unacknowledged. `TCP_NODELAY` disables.
- **Delayed ACK (receiver):** wait 40–200 ms for a second segment or data to piggyback on.

Together: two small `send()` calls → Nagle holds the second, delayed ACK holds the ACK → ~40 ms of
nothing. **Fix: write the whole message in one `send()`/`writev()`.** Nagle only holds back *small*
writes following unacknowledged data. Add `TCP_NODELAY` for RPC/interactive workloads.

### MSS vs MTU

| Path | MTU | IPv4 MSS |
|---|---|---|
| Ethernet | 1500 | 1460 |
| Ethernet + IPv6 | 1500 | 1440 |
| PPPoE (DSL) | 1492 | 1452 |
| VPN / WireGuard | ~1420 | ~1380 |
| Jumbo frames | 9000 | 8960 |

**PMTU black hole:** a router needs to reply ICMP Type 3 Code 4 ("fragmentation needed"). Firewalls
that block all ICMP break this — handshake succeeds, first full-size segment vanishes, connection
hangs. Symptom: **small requests work, large ones stall forever.** Mitigate with
`net.ipv4.tcp_mtu_probing=1`.

---

## 7. Loss & congestion

**Two loss signals, very different meanings:**

1. **RTO expires** — pessimistic. `cwnd = 1`, restart slow start, double the timer (exponential backoff).
2. **3 duplicate ACKs** — optimistic. Data still flows, so retransmit immediately and halve cwnd.
   This is **fast retransmit**.

Three, not one, because the network reorders packets and one duplicate is not evidence of loss.

**RTO (RFC 6298 / Jacobson-Karels):**

```
RTTVAR = 0.75 × RTTVAR + 0.25 × |SRTT − R|
SRTT   = 0.875 × SRTT   + 0.125 × R
RTO    = SRTT + 4 × RTTVAR      (clamped to ≥ 1 s)
```

Including *variance* is the key: a steady 200 ms path gets a tight timeout, a jittery mobile link
with the same average gets a generous one. **Karn's algorithm:** never sample RTT from a
retransmitted segment — you can't tell which copy the ACK answers.

**SACK (RFC 2018):** a plain ACK is cumulative and cannot describe a gap. SACK attaches up to 3–4
blocks of already-received ranges: `ACK ack=2921 SACK=4381–8761` → "I'm missing 2921–4380, I already
have 4381 through 8760." The sender retransmits precisely the hole.

**The four phases:**

| Phase | Behaviour |
|---|---|
| Slow start | cwnd starts at **10** segments (RFC 6928), **×2 per RTT** — exponential |
| Congestion avoidance | past ssthresh, **+1 segment per RTT** — linear |
| Fast retransmit / recovery | 3 dup ACKs → resend, `ssthresh = cwnd/2`, `cwnd = ssthresh` |
| Timeout | `ssthresh = cwnd/2`, **`cwnd = 1`**, back to slow start — expensive |

AIMD (additive increase, multiplicative decrease) is what makes independent flows converge on a fair
share of a link without ever communicating.

**Algorithms:** Reno/NewReno (the reference) · **CUBIC** (Linux & Windows default) ·
**BBR** (models bandwidth & RTT instead of reacting to loss — strong on lossy wireless and bloated
buffers) · Vegas (delay-based, loses against loss-based flows).

**Bufferbloat:** big router buffers queue instead of dropping, so loss-based control fills them and
adds hundreds of ms of latency. ECN sidesteps it — routers *mark* instead of dropping, receiver
echoes with `ECE`.

```bash
sysctl net.ipv4.tcp_congestion_control            # cubic
sysctl net.ipv4.tcp_available_congestion_control  # reno cubic bbr
```

---

## 8. Closing

A connection is **two independent one-way streams**, each shut down separately — hence four segments.
FIN means *"I have no more data to send; you may keep sending"* (**half-close**), not "goodbye."

```
1. FIN, ACK  →   client: FIN_WAIT_1
2.      ACK  ←   server: CLOSE_WAIT     client: FIN_WAIT_2
3. FIN, ACK  ←   server: LAST_ACK
4.      ACK  →   client: TIME_WAIT      server: CLOSED
```

Steps 2 and 3 are commonly coalesced into one `FIN, ACK` → a three-segment close. **RST** is the
abortive alternative: not acknowledged, queued data discarded, no TIME_WAIT.

**TIME_WAIT = 2 × MSL** (RFC: 4 min; Linux: hardcoded 60 s). Two real reasons:

1. The final ACK may be lost — someone must still be there to answer the retransmitted FIN.
2. Delayed duplicates from the old connection must expire before the four-tuple is reused.

- `net.ipv4.tcp_tw_reuse = 1` — reasonable, client-side, timestamp-guarded.
- `net.ipv4.tcp_tw_recycle` — **do not use.** Broke NAT'd clients; *removed from Linux in 4.12*.
- Real fix: pool and keep connections alive. Prefer having the *client* close first.

**CLOSE_WAIT is always your bug.** Leaving it requires *your application* to call `close()`. There is
no timeout. A pile of CLOSE_WAIT = leaked file descriptors, never a tuning problem.

**Keepalive** defaults are useless for most services (`7200 / 75 / 9` → ~2h11m to notice a dead peer).
Use an application-level heartbeat instead.

---

## 9. Checksum

Ones'-complement sum with **end-around carry**, then complemented. Receiver sums everything
*including* the checksum; a valid segment sums to `0xFFFF` → complement `0x0000`.

```
  0xE34F + 0x2396 = 0x106E5  →  0x06E5 + 1 = 0x06E6   (end-around carry)
  0x06E6 + 0x4427 = 0x4B0D
  checksum = ~0x4B0D = 0xB4F2
  check:  0x4B0D + 0xB4F2 = 0xFFFF  →  ~0xFFFF = 0x0000  ✓
```

It also covers a **12-byte pseudo-header** that is never transmitted: src IP (4) + dst IP (4) +
zero (1) + protocol=6 (1) + TCP length (2). Consequences:

- **NAT must recompute it** — which is why NAT is a transport-layer operation.
- **Weak** (16 bits) — a last-resort check on top of Ethernet's CRC32.
- **Offloaded to the NIC** — hence `cksum incorrect` in tcpdump on the *sending* host. Not a bug.
- **Mandatory in TCP**, unlike UDP over IPv4.

---

## 10. TCP under HTTP

**Does every API call cost a handshake? No — not since 1997.**

| Version | Transport | Connections | New handshake per request? |
|---|---|---|---|
| HTTP/1.0 | TCP | one per request | Yes (`keep-alive` existed as a non-standard extension) |
| HTTP/1.1 | TCP | persistent; ~6 per origin in browsers | No — reused until idle timeout or `Connection: close` |
| HTTP/2 | TCP + TLS | one per origin | No — concurrent streams multiplexed |
| HTTP/3 | **QUIC / UDP** | one per origin | No TCP at all; 1-RTT, or 0-RTT on resumption |

Four requests: **HTTP/1.0 = 8 RTT · HTTP/1.1 = 5 RTT · HTTP/2 = 2 RTT** (TLS omitted; add 1 RTT per
new connection).

Refinements to the original analysis:

1. **HTTP/2 does not remove head-of-line blocking** — only at the *HTTP* layer. All streams still ride
   one TCP connection, and **TCP delivers bytes strictly in order**. One lost segment stalls *every*
   stream. On a lossy link HTTP/2 can be slower than HTTP/1.1 with 6 connections. That is the entire
   reason HTTP/3 abandoned TCP.
2. **Pools are keyed by `(scheme, host, port)`** — plus top-level site in modern browsers for privacy.
   Two hostnames on the same IP still get separate pools, *except* HTTP/2 connection coalescing when
   the TLS cert covers both.
3. **Servers close connections too** — nginx `keepalive_requests` 1000 / `keepalive_timeout` 75s,
   AWS ALB idle 60s. **Always set the client's idle timeout shorter than the server's**, or you get
   intermittent 502s on reused connections the balancer already closed.
4. **Share one persistent client:** Go → one `http.Client` package-level · Python →
   `requests.Session()` / `httpx.Client()` · Node → Agent with `keepAlive:true` or undici Pool ·
   Java → one `OkHttpClient` · .NET → `IHttpClientFactory`. Failure mode: works in dev, exhausts
   ephemeral ports in prod.

---

## 11. Seeing it

```bash
# capture
sudo tcpdump -i any -n -S 'host example.com and tcp port 80'
curl -s -o /dev/null http://example.com/

# tcpdump flag shorthand:  S=SYN  S.=SYN+ACK  .=ACK  P.=PSH+ACK  F.=FIN+ACK  R=RST
#   the dot IS the ACK bit

ss -tin                                        # per-socket cwnd, rtt, retrans
ss -tan | awk 'NR>1 {print $1}' | sort | uniq -c | sort -rn   # states histogram
ss -tan state close-wait                       # the leak check
ss -lnt                                        # Recv-Q = accept queue depth, Send-Q = its limit
nstat -az | grep -Ei 'retrans|TCPTimeouts|ListenDrops'
```

Wireshark filters: `tcp.analysis.retransmission` · `tcp.analysis.duplicate_ack` ·
`tcp.analysis.zero_window` · `tcp.flags.reset==1` · `tcp.time_delta > 0.2` · `tcp.stream eq 0`.
*Statistics → TCP Stream Graphs → Time Sequence (Stevens)* plots the sawtooth from real data.

---

## 12. Triage table

| Symptom | Likely cause | Check |
|---|---|---|
| Small requests fine, large ones hang | PMTU black hole, ICMP blocked | `tcp_mtu_probing`, lower MSS |
| Latency spikes of ~40 ms | Nagle × delayed ACK | one write per message; `TCP_NODELAY` |
| `EADDRNOTAVAIL` under load | ephemeral ports exhausted by TIME_WAIT | `ss -tan \| grep -c TIME-WAIT` |
| Sockets pile up in CLOSE_WAIT | your code never calls `close()` | `ss -tan state close-wait` |
| Fast link, terrible throughput | window scaling stripped by a middlebox | compare `wscale` in both SYNs |
| Intermittent 502s behind an LB | client idle timeout > LB idle timeout | lower client keep-alive |
| Transfer stalls then resumes | receiver advertised zero window | `tcp.analysis.zero_window` |
| Connection dies after idle | NAT/firewall dropped the state | app-level heartbeat |

---

## Reference card

- **Header** 20 B min / 60 B max · Data Offset 5–15 words · options ceiling 40 B · 8 control bits, 4 reserved
- **Ports** 0–1023 / 1024–49151 / 49152–65535 · Linux actually 32768–60999
- **Sizes** MTU 1500 → MSS 1460 (IPv4), 1440 (IPv6) · window field max 65,535 B, scaled max 1 GiB
- **Timers** RTO = SRTT + 4·RTTVAR, floor 1 s · TIME_WAIT 2×MSL = 60 s on Linux · delayed ACK 40–200 ms
- **Congestion** IW 10 · slow start ×2/RTT · avoidance +1/RTT · 3 dup ACKs → cwnd÷2 · timeout → cwnd=1
- **Arithmetic** `next_seq = seq + len (+1 if SYN|FIN)` · `ack = next byte expected` · `in flight ≤ min(rwnd, cwnd)`
