# CyberQuest 2025 - Final - Mission: Comission? #1

## Description

# Mission: Comission? #1

You walk in a dark forest. An IoT device pops up. What do you do? Lumos!

fyi: The QR code isn't what you would expect. An owl hoots: You are lookig for an XOR encrypted 2 byte key.

> Remarks from the authors:
> * You will need the provided hardware.
> * Start with this challenge first.
> * Device needs to be USB powered. There is no battery. You should see some e-ink flashes.
> * The device is already on the Wi-Fi network, there is no need for special Bluetooth LE equipment.
> * If a pairing/commissioning fails for whatever reason, it is recommended to restart the device before the next try. Click the small RST button shortly on the device.

**Flag format**: `CQ25{...}`

Challenge difficulty: `easy/medium`

*Proudly sponsored by CUJO AI*

## Metadata

- Filename: -
- Tags: `iot`, `matter`

## Solution

We got an IoT device, which had an e-ink display with a QR-code and the `matter` string.

The QR code is a base64 encoded byte array.

The description suggest that we need a 2-byte XOR key.

[Matter](https://en.wikipedia.org/wiki/Matter_(standard)) is a standard for IoT devices and smart homes for communication with a single protocol. To commission a device we need a QR code or a string starting with `MT:`.

If we brute-force the XOR key and search for `MT:`, the result is the following:

```
MT:Y.K90Y.G27B-3S65C00
```

The XOR key is `4142`.

I used the `homeassistant` and `matter-server` docker images to set up a smart home infrastructure.

```bash
docker run \
  --name homeassistant \
  --privileged \
  --restart=unless-stopped \
  -v ${PWD}:/config \
  -v /run/dbus:/run/dbus:ro \
  --network=host \
  ghcr.io/home-assistant/home-assistant:stable
```

```bash
docker run \
  --name matter-server \
  --restart=unless-stopped \
  --security-opt apparmor=unconfined \
  -v $(PWD)/data:/data \
  --network=host \
  ghcr.io/matter-js/python-matter-server:stable
```

In the `homeassistant` server it is possible to commission a device using the `MT:Y.K90Y.G27B-3S65C00` code, but before I had to join the `CyberQuest` wireless network, to which the device is also connected.

After successful commissioning the device presents the flag on the display:

Flag: `CQ25{c0mm1ss10n_m4tt3rs}`