# p-net test peer

A Docker image with the open-source [p-net](https://github.com/rtlabs-com/p-net) Profinet device
stack's sample application, used as the device in `internal/profinet`'s `TestConnectToDevice`.
p-net is GPL v3; it is fetched and built inside the image and only talks to plc4go over a veth
pair, so nothing from it is linked into plc4go.

```sh
docker build -t pnet-peer plc4go/tools/pnet-peer
docker run --rm --privileged -v "$PWD":/src -w /src/plc4go pnet-peer sh tools/pnet-peer/run-test.sh
```

Notes:

- The image builds p-net **v0.2.0**: the public repository's later tags no longer carry the CMake
  build or the sample application.
- A veth link reports no copper or fiber port type, so p-net would refuse the parameterization
  end for lack of a fast enough port. The image patches p-net to treat an unknown medium as
  100BASE-TX full duplex. Nothing else is changed.
- Build with `--build-arg LOG_LEVEL=DEBUG` to see p-net's state machines.
- The sample device reports only its head module (slot 0) before a controller connects, so the
  test establishes the application relation and the cyclic exchange without process data.
- The same test runs against a Raspberry Pi with p-net or any real device: set
  `PROFINET_TEST_INTERFACE`, `PROFINET_TEST_DEVICE` (name of station) and `PROFINET_TEST_GSD`
  (a directory holding its GSDML).
