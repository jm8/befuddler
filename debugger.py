#!/usr/bin/env python3
from pathlib import Path
import time
import re
import shutil


def render():
    log = Path("./gdb.txt").read_text()

    addr = 0
    for match in re.finditer(r"STACK\(\(0x([0-9a-f]+)\)\)", log):
        addr = int(match[1], 16)

    for match in re.finditer(r"WIDTH\(\(0x([0-9a-f]+)\)\)", log):
        width = int(match[1], 16)

    for match in re.finditer(r"HEIGHT\(\(0x([0-9a-f]+)\)\)", log):
        height = int(match[1], 16)

    program_start = 0
    for match in re.finditer(r"PROGRAM_START\(\(0x([0-9a-f]+)\)\)", log):
        program_start = int(match[1], 16)

    funge_space = b""
    for match in re.finditer(r"FUNGE_SPACE\(\(([0-9a-f]+)\)\)", log):
        funge_space = bytes.fromhex(match[1])

    script = []
    for i in range(height):
        start = (width + 4) * i
        end = start + width
        script.append(
            "".join(
                " " if not 32 <= c <= 127 else chr(c) for c in funge_space[start:end]
            )
        )

    offset = addr - program_start
    offset_instrs = offset // 10
    yy, xx = divmod(offset_instrs, width + 4)

    RED = "\033[41m"
    RESET = "\033[0m"
    CLEAR = "\033[2J\033[H"

    term_width, term_height = shutil.get_terminal_size()

    PAD = 4

    if yy > term_height - PAD:
        term_y_off = yy - PAD
    else:
        term_y_off = 0

    if xx > term_width - PAD:
        term_x_off = xx - PAD
    else:
        term_x_off = 0

    screen = ""
    for y, line in enumerate(script):
        if not (term_y_off <= y < term_y_off + term_height):
            continue

        for x, c in enumerate(line):
            if not (term_x_off <= x < term_x_off + term_width):
                continue

            if (y, x) == (yy, xx):
                screen += f"{RED}{c}{RESET}"
            else:
                screen += f"{c}"
        screen += "\n"
    print(f"{CLEAR}{screen}")


while True:
    render()
    time.sleep(5)
