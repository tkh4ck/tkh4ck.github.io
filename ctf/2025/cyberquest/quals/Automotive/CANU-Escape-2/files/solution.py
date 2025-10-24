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