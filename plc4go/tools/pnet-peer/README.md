# p-net test peer

A Docker image with the open-source [p-net](https://github.com/rtlabs-com/p-net) Profinet device
stack's sample application, used as the device in `internal/profinet`'s `TestConnectToDevice` and
`TestDeviceAlarms`.
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
- The sample device reports only its head module (slot 0) before a controller connects and plugs
  what the controller expects. The test puts the echo module (`IDM_40`) in slot 1 with the
  connection option `module.1=IDM_40`, writes a REAL and a UDINT to its outputs and reads them
  back from its inputs, times the gain parameter (GSDML default 2, p-net's own default 1, so the
  doubling also shows the parameter record write took effect). `PROFINET_TEST_ECHO_SLOT=` (empty)
  skips that part.
- The same test runs against a Raspberry Pi with p-net or any real device: set
  `PROFINET_TEST_INTERFACE`, `PROFINET_TEST_DEVICE` (name of station) and `PROFINET_TEST_GSD`
  (a directory holding its GSDML).
- `TestDeviceAlarms` presses the sample device's button 2, a file the script hands it with
  `pn_dev -d`, to make it raise alarms from the 8-bit input module (`IDM_30`) it puts in slot 2: a
  process alarm (high priority), then, after two presses that switch the cyclic data to backup
  and back, a channel diagnosis (low priority). The test checks each alarm reaches an `ALARM:2`
  subscription and that the device acknowledges the driver's AlarmAck. On a Pi, set
  `PROFINET_TEST_ALARM_BUTTON` to the file given to `pn_dev -d`.
- `PNET_ARGS` adds arguments to `pn_dev`, e.g. `-e PNET_ARGS=-vvv` for the sample application's
  own log. Its output to a file is block buffered, so lines can be missing when the container
  stops; run it under `stdbuf -oL` to see everything.
- `-e PROFINET_TEST_RPC_FRAGMENT_SIZE=128` sets the connection option `rpc-fragment-size`, so the
  connect requests go out as DCE/RPC fragments, which p-net acknowledges and reassembles. Its
  Connect would otherwise fit one datagram.
