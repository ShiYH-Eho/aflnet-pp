# AFLNet network protocol test tools

Standalone replayers for network protocol servers, ported from the original
[AFLNet](https://github.com/aflnet/aflnet) repository into aflnet-pp.

They are small client programs: they connect to a server under test on
`127.0.0.1`, replay a recorded test case, and print the response codes the
server produced. They are the tools ProFuzzBench's `crash_script` and
`cov_script.sh` call to reproduce a crash or to measure the coverage reached by
a saved test case.

Unlike the fuzzer, the replayers do **not** need the server to be compiled
with instrumentation, and they do not use any shared memory. They speak plain
TCP/UDP.

## Tools

| Tool            | Input format                                                                 | Use case |
| --------------- | ---------------------------------------------------------------------------- | -------- |
| `aflnet-replay` | structured: repeated `[4-byte size (host order)][message bytes]`              | the AFLNet `replayable-*` corpus (`save_testcase_to_file(..., replay_enabled=1)`) |
| `afl-replay`    | raw: the whole file is one blob, message boundaries are not marked            | the `queue` / `crashes` corpus where messages are concatenated |

`aflnet-replay` sends one message at a time and waits for a response after
each, while `afl-replay` sends everything at once and collects the responses.

## Building

```bash
make -C utils/aflnet
```

`make` at the repository root also builds them (see the `all` target), and
`make install` installs both binaries into `$(PREFIX)/bin` together with this
README.

## Usage

```bash
aflnet-replay <packet_file> <protocol> <port> [first_resp_timeout(ms)] [follow-up_resp_timeout(us)]
afl-replay    <packet_file> <protocol> <port> [first_resp_timeout(ms)] [follow-up_resp_timeout(us)]
```

Arguments:

* **packet_file** – the test case to replay.
* **protocol** – application protocol, case-insensitive (e.g. `FTP`, `ftp`).
* **port** – the server's port.
* **first_resp_timeout** – `poll()` timeout in **ms**, default `1`.
* **follow-up_resp_timeout** – socket send/recv timeout in **us**, default `1000`.

Example, reproducing a saved FTP crash:

```bash
./aflnet-replay replayable-crashes/id:000000,sig:11 out 21 1
```

The `-h` / `--help` flag prints the usage without touching the network.

## Supported protocols

The protocol parsers are shared with the fuzzer: both tools link
`src/aflnet/protocols.c`, the very same file `afl-fuzz` uses, so the two can
never drift apart. The dispatch lives in
`utils/aflnet/replay-net.c` (`replay_response_code_extractor()`).

`SMTP`, `SSH`, `TLS`, `DICOM`, `DNS`, `FTP`, `MQTT`, `RTSP`, `DTLS12`/`DTLS`,
`SIP`, `HTTP`, `IPP`, `DHCP`, `TFTP`, `SNTP`, `NTP`, `SNMP`.

Datagram protocols (`DNS`, `DHCP`, `TFTP`, `SNTP`, `NTP`, `SNMP`, `DTLS12`,
`SIP`) use `SOCK_DGRAM`; everything else uses `SOCK_STREAM`. This mirrors the
fuzzer's `aflnet_protocol_to_socket_type()`.

## Files

* `aflnet-replay.c` – structured replayer (`main`).
* `afl-replay.c` – raw replayer (`main`).
* `replay-net.c` / `replay-net.h` – shared helpers: file loading, protocol
  dispatch, connect-with-retry, poll()-based send/recv (a faithful port of
  AFLNet's `net_send()`/`net_recv()`), result printing.
* `GNUmakefile` – build/install rules.

## Notes on the port

* The output format is byte-for-byte the one the original replayers used
  (`Responses from server: ...` followed by the raw response dump), so existing
  scripts that parse it keep working.
* Protocol name matching is case-insensitive, an improvement over the original
  which required the exact uppercase spelling.
* `replay_net_recv()` treats a timeout as "no more data", matching upstream;
  the replayer therefore terminates instead of hanging when the server stays
  alive after consuming all requests.
