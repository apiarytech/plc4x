# OPC UA test peers

A Docker image with two OPC UA servers written independently of PLC4X, used as the servers in
`internal/opcua`'s `Connection_server_test.go`:

| Server | Language | Version |
|---|---|---|
| [open62541](https://github.com/open62541/open62541) | C, mbedTLS | v1.4.22 |
| [asyncua](https://github.com/FreeOpcUa/opcua-asyncio) | Python | 2.1.0 |

open62541 is MPL 2.0 and asyncua LGPL 3.0; both are fetched and built inside the image and only
talk to plc4go over TCP, so nothing from them is linked into plc4go.

```sh
docker build -t opcua-peer plc4go/tools/opcua-peer
docker run --rm -v "$PWD":/src -w /src/plc4go opcua-peer sh tools/opcua-peer/run-test.sh
```

`run-test.sh` starts each server in turn with a fresh certificate and runs the tests against it.
Both serve the same address space (`open62541_server.c`, `asyncua_server.py`) in namespace 2:

| Node | What |
|---|---|
| `Demo` | folder |
| `Demo.Bool`, `Int16`, `Int32`, `Int64`, `UInt32`, `Float`, `Double`, `String` | read-only scalars |
| `Demo.Int32Array` | `[1, 2, 3]`, one dimension of 3 |
| `Demo.Counter` | Int32, counts up every 100 ms |
| `Demo.ReadOnly` | Int32, not writable |
| `Demo.WritableInt32`, `WritableDouble`, `WritableBool`, `WritableString` | writable |

Logins are anonymous and `operator`/`secret`. asyncua lets anonymous users read but not write.

The tests cover:

- reading every scalar type and an array, and the status of an unknown node;
- browsing the `Demo` folder (data types, array dimensions, access levels);
- a change-of-state subscription on `Demo.Counter`: values arrive once each, in order;
- writes and reading them back, a write to a read-only node (`ACCESS_DENIED`) and to an unknown
  node;
- a wrong password, which is refused;
- Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss, each with SIGN and
  SIGN_ENCRYPT, as `operator`, with the server's certificate pinned
  (`server-certificate-file`);
- a pinned certificate that is not the server's, which is refused.

The same tests run against any server with this address space: set `OPCUA_TEST_ENDPOINT`
(`host:port`) and, for the secured channels, `OPCUA_TEST_SERVER_CERTIFICATE`.

Notes:

- With a pinned certificate that is not the server's, open62541 closes the channel at once;
  asyncua cannot decrypt the request and does not answer, so the connection fails after the
  handshake timeout (30 s).
- asyncua answers a write to an unknown node with BadUserAccessDenied, open62541 with
  BadNodeIdUnknown; the test takes either.
