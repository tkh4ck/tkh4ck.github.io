# CyberQuest 2025 - CANU Escape #2

## Description

Amaz*e*ing job on the first one! But no CTF is complete without path finding. Can you figure?

> Remarks from the author:
> * the challenge requires some brute-forcing... In the respect that you aren't given controls directly, so you gotta observe. You don't need to pull random numbers out though.
> * VPN connection is required
> * the challenge runs on two ports

**Flag format**: `CQ25{...}`

Challenge difficulty: `hard`

*By MJ - Contact me on Discord with the same nick if you think you found an issue or open a ticket in #help-tickets.*

```
cq25-challenge0[1-9]-c.cq.honeylab:8080
cq25-challenge0[1-9]-c.cq.honeylab:29536
```

## Metadata

- Filename: -
- Tags: `can`

## Solution

For the second flag we have to move the "car" to collect all prices (plus signs) in the map.

By analysing the CAN messages we can derive that messages id `0x456` controls the movement to the four directions:

```
< frame 456 1758935672.377468 13 >
< frame 456 1758935673.377211 12 >
< frame 456 1758935674.377334 13 >
< frame 456 1758935675.377261 13 >
< frame 456 1758935677.377571 13 >
< frame 456 1758935678.377393 12 >
< frame 456 1758935679.377094 12 >
< frame 456 1758935680.377045 11 >
< frame 456 1758935681.377030 10 >
```

The following Python script can be used to move the car using the arrow keys ([`solution.py`](files/solution.py)):

```python
import curses
import can

def main(stdscr):
    # Turn off cursor and enable keypad mode
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.nodelay(False)  # Block for input

    stdscr.addstr(0, 0, "Press arrow keys (or 'q' to quit)")

    bus = can.interface.Bus(interface='socketcand', host="10.10.100.113", port=29536, channel="can0")

    while True:
        key = stdscr.getch()
        stdscr.clear()

        if key == curses.KEY_UP:
            stdscr.addstr(1, 0, "You pressed UP ⬆️")
            msg = can.Message(arbitration_id=0x456, data=[0x11])
            bus.send(msg)
        elif key == curses.KEY_DOWN:
            stdscr.addstr(1, 0, "You pressed DOWN ⬇️")
            msg = can.Message(arbitration_id=0x456, data=[0x12])
            bus.send(msg)
        elif key == curses.KEY_LEFT:
            stdscr.addstr(1, 0, "You pressed LEFT ⬅️")
            msg = can.Message(arbitration_id=0x456, data=[0x13])
            bus.send(msg)
        elif key == curses.KEY_RIGHT:
            stdscr.addstr(1, 0, "You pressed RIGHT ➡️")
            msg = can.Message(arbitration_id=0x456, data=[0x14])
            bus.send(msg)
        elif key == ord('q'):
            bus.shutdown()
            break
        else:
            stdscr.addstr(1, 0, f"Other key: {key}")

        stdscr.refresh()

curses.wrapper(main)
```

```
You won!
Flag: CQ25{huh_h0w_d1d_y4_w1n?_ru_@_haCk3r?}
```

Flag: `CQ25{huh_h0w_d1d_y4_w1n?_ru_@_haCk3r?}`