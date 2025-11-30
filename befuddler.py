#!/usr/bin/env python3
from argparse import ArgumentParser
from pathlib import Path
import subprocess
import struct
from instruction_loader import InstructionLoader

REG_DIRECTION = "r12"
REG_RET_ADDR = "r14"

DIR_RIGHT = 0
DIR_DOWN = 1
DIR_LEFT = 2
DIR_UP = 3

DEFAULT_WIDTH = 80
DEFAULT_HEIGHT = 25

RED = "\033[31m"
YELLOW='\033[33m'
RESET = "\033[0m"

def parse_befunge(source: str, width: int, height: int):
    if "\t" in source:
        print(f"{YELLOW}WARNING:{RESET} tab found in source")

    lines = source.splitlines()
    lines = lines[:height]
    result = [list(line[:width].ljust(width)) for line in lines]
    result.extend([[" "] * width] * (height- len(result)))
    return result


def compile_befunge(befunge: list[list[str]],
                    width: int, height: int, b98: bool,
                    debug: bool):
    instruction_functions = ""

    instruction_loader = InstructionLoader(width, height, b98)

    defined_instructions = instruction_loader.defined_instructions
    instruction_names = instruction_loader.instruction_names

    for char, code in defined_instructions.items():
        name = instruction_names[char]
        instruction_functions += f"""
{name}:
    pop {REG_RET_ADDR}
{code}
    push {REG_RET_ADDR}
    ret
"""

    code_space = ""

    for i in range(-2, height + 2):
        for j in range(-2, width+ 2):
            if (i, j) == (0, 0):
                code_space += f"""
program_start:"""
            if i < 0:
                name = "top_edge"
            elif i >= height:
                name = "bottom_edge"
            elif j < 0:
                name = "left_edge"
            elif j >= width:
                name = "right_edge"
            else:
                name = instruction_names.get(befunge[i][j])
                if debug:
                    if name:
                        print(f"{RESET}{befunge[i][j]}", end="")
                    else:
                        print(f"{RED}{befunge[i][j]}{RESET}", end="")
            if name:
                code_space += f"""
    call {name}"""
            elif b98:
                code_space += f"""
    call reflect"""
            else:
                code_space += f"""
    nop""" * 5
            code_space += f"""
    call nexti"""
        if debug:
            print()

    funge_space = ""
    for y, row in enumerate(befunge):
        for x, instruction in enumerate(row):
            funge_space += f"""
    .byte {ord(instruction)}"""
        funge_space += f"""
    .byte 0""" * 4

    instruction_lut = ""
    for i in range(256):
        default_instruction = "reflect" if b98 else "nop"
        function_name = instruction_names.get(chr(i), default_instruction)
        instruction_lut += f"""
    .quad {function_name}"""

    return f""".intel_syntax noprefix

.file "compiled.s"
.globl main

.data

funge_space:
{funge_space}

rand_seed:
    .quad 0

.section .rodata
error_bad_write:
    .string "ERROR: Attempt to write outside of funge-space\\n"
error_bad_read:
    .string "ERROR: Attempt to read outside of funge-space\\n"

direction_deltas:
    # used for quotes
    .quad 10 # right
    .quad {(width + 4) * 10} # down
    .quad -10 # left
    .quad {-(width + 4) * 10} # up

instruction_lut:
{instruction_lut}

.text

{instruction_functions}

nop:
    ret

left_edge:
    pop r14
    sub r14, 5
    add r14, {width * 10}
    push r14
    ret

right_edge:
    pop r14
    sub r14, 5
    sub r14, {width * 10}
    push r14
    ret

top_edge:
    pop r14
    sub r14, 5
    add r14, {((width + 4) * height) * 10}
    push r14
    ret

bottom_edge:
    pop r14
    sub r14, 5
    sub r14, {((width + 4) * height) * 10}
    push r14
    ret

in_range:
    # check if x=rdi, y=rsi is in range
    # return iff in range
    mov rax, 1
    cmp rdi, {width}
    jb x_in_range
    dec rax
    jmp in_range_exit
x_in_range:
    cmp rsi, {height}
    jb in_range_exit
    dec rax
in_range_exit:
    ret

nexti:
    pop r14
    mov rdx, [direction_deltas + {REG_DIRECTION}*8]
    sub r14, 10
    add r14, rdx
    push r14
nexti_exit:
    ret

print_error_and_exit:
    # assume error in rdi
    mov rsi, rdi
continue_printing_error:
    mov al, byte ptr [rsi]
    test al, al
    jz exit_with_error

    mov rax, 1
    mov rdi, 1
    mov rdx, 1
    syscall

    inc rsi
    jmp continue_printing_error
exit_with_error:
    mov rax, 60
    mov rdi, 1
    syscall

update_line_char:
    # assume line and char in rdi and rsi
    cmp {REG_DIRECTION}, {DIR_RIGHT}
    jne update_line_char_dir_not_right

    inc rsi
    cmp rsi, {width}
    jne line_char_updated
    mov rsi, 0

    jmp line_char_updated
update_line_char_dir_not_right:
    cmp {REG_DIRECTION}, {DIR_LEFT}
    jne update_line_char_dir_up_or_down

    dec rsi
    cmp rsi, -1
    jne line_char_updated
    mov rsi, {width - 1}

    jmp line_char_updated
update_line_char_dir_up_or_down:
    cmp {REG_DIRECTION}, {DIR_DOWN}
    jne update_line_char_dir_up

    inc rdi

    cmp rdi, {height}
    jne line_char_updated
    mov rdi, 0

    jmp line_char_updated
update_line_char_dir_up:

    dec rdi
    cmp rdi, -1
    jne line_char_updated
    mov rdi, {height - 1}
line_char_updated:
    ret

main:
    # set up rand seed
    mov eax, 1
    cpuid

    bt ebx, 18
    jc has_rdseed

    bt ecx, 30
    jc has_rdrand

    rdtsc
    shl rdx, 32
    or rax, rdx
    jmp seed_in_rax

has_rdrand:
    rdrand rax
    jmp seed_in_rax

has_rdseed:
    rdseed rax

seed_in_rax:
    mov qword ptr [rand_seed], rax

    # save rsp
    mov rbp, rsp

    # reserve 0x1000 zero bytes on the stack
    sub rsp, 0x1000
    lea rdi, [rsp]
    mov rcx, 0x1000
    xor al, al
    rep stosb

    xor {REG_DIRECTION}, {REG_DIRECTION}

    jmp program_start
{code_space}
"""


def get_fit_size(source: Path):
    max_len = 0
    line_count = 0

    with source.open("r", encoding="latin-1") as f:
        for line in f:
            line_count += 1
            max_len = max(max_len, len(line.rstrip("\n")))

    width = max_len
    height = line_count
    return width, height
    

def main():
    parser = ArgumentParser(
        prog="Befuddler",
        description="Befunge compiler"
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--width", type=int, default=DEFAULT_WIDTH)
    parser.add_argument("--height", type=int, default=DEFAULT_HEIGHT)
    parser.add_argument("--fit_size", action="store_true",
                        help="set size to fit source")
    parser.add_argument("--b98", action="store_true",
                        help="enable minimal funge-98 support")

    args = parser.parse_args()

    if args.fit_size:
        width, height = get_fit_size(args.source)
        print(f"Detected (width, height): ({width}, {height})")
    else:
        width = args.width
        height = args.height


    parsed = parse_befunge(args.source.read_text("latin-1"), width, height)
    compiled = compile_befunge(parsed, width, height, args.b98, args.debug)
    asm = args.source.with_suffix(".s")
    exe = args.source.with_name(args.source.stem)
    asm.write_text(compiled)
    print("Wrote", asm)
    subprocess.run(["gcc", asm, "-o", exe, "-no-pie"], check=True)

    elf_bytes = bytearray(exe.read_bytes())
    phoff = struct.unpack_from("<Q", elf_bytes, 0x20)[0]
    phnum = struct.unpack_from("<H", elf_bytes, 0x38)[0]
    for i in range(phnum):
        flags_off = phoff + 0x38 * i + 0x4
        p_flags = struct.unpack_from("<I", elf_bytes, flags_off)[0]
        if p_flags & 0x1:
            elf_bytes[flags_off : flags_off + 4] = b"\x07\x00\x00\x00"
    exe.write_bytes(elf_bytes)


if __name__ == "__main__":
    main()
