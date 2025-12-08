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

MAX_FINGERPRINT_LEN = 8
MAX_INPUT_LEN = 32

STACK_ZERO_SIZE = 0x1000

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

    if b98:
        semantic_lut = f"""
    .quad reflect""" * 26
        fingerprint_table = ""
        fingerprint_sections = ""
        for fingerprint_id, functions in instruction_loader.fingerprints.items():
            fingerprint_sections += f"""
{fingerprint_id}:"""

            fingerprint_table += f"""
    .ascii "{fingerprint_id}"
    .zero {MAX_FINGERPRINT_LEN - len(fingerprint_id)}
    .quad {fingerprint_id}
            """
            for char, name, code in functions:
                fingerprint_sections += f"""
    .quad {ord(char) - ord('A')}
    .quad {name}
"""

                instruction_functions += f"""
{name}:
    pop {REG_RET_ADDR}
{code}
    push {REG_RET_ADDR}
    ret
"""
            fingerprint_sections += f"""
    .quad -1
"""
        fingerprint_table += f"""
    .zero {MAX_FINGERPRINT_LEN}
"""

        input_buf = f"""
    .zero {MAX_INPUT_LEN}"""
        b98_data = f"""
input_buf:
{input_buf}

{fingerprint_sections}

fingerprint_table:
{fingerprint_table}

semantic_lut:
{semantic_lut}
"""
    else:
        b98_data = f""

    if b98:
        nexti = f"""
    pop r14
    test {REG_DIRECTION}, 4
    jnz nexti_not_cardinal
    mov rdx, [direction_deltas + {REG_DIRECTION}*8]
    sub r14, 10
    add r14, rdx
    push r14
    jmp nexti_exit
nexti_not_cardinal:
    mov rax, {REG_DIRECTION}
    shr rax, 3
    mov rsi, rax # dx
    shr rax, 16
    mov rdi, rax # dy
    movsx rsi, si
    movsx rdi, di
    call get_line_char
    add rdi, rax # y
    add rsi, rdx # x

    mov rax, rdi
    cqo
    mov rcx, {height}
    idiv rcx
    mov rdi, rdx

    mov rax, rsi
    cqo
    mov rcx, {width}
    idiv rcx
    mov rsi, rdx
    call set_line_char
    sub r14, 15
    push r14
nexti_exit:
    ret
"""
    else:
        nexti = f"""
    pop r14
    test {REG_DIRECTION}, 4
    mov rdx, [direction_deltas + {REG_DIRECTION}*8]
    sub r14, 10
    add r14, rdx
    push r14
nexti_exit:
    ret
"""

    return f""".intel_syntax noprefix

.file "compiled.s"
.globl main

.data

funge_space:
{funge_space}

{b98_data}

rand_seed:
    .quad 0

    # in data section for b98 fingerprint overriding
instruction_lut:
{instruction_lut}

.section .rodata
error_bad_write:
    .string "ERROR: Attempt to write outside of funge-space\\n"
error_bad_read:
    .string "ERROR: Attempt to read outside of funge-space\\n"
error_undefined_value:
    .string "ERROR: Attempt to access undefined value\\n"

# for debugger
width:
    .quad {width}
height:
    .quad {height}

direction_deltas:
    # used for quotes
    .quad 10 # right
    .quad {(width + 4) * 10} # down
    .quad -10 # left
    .quad {-(width + 4) * 10} # up

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

reflect:
    test {REG_DIRECTION}, 4
    jz reflect_is_cardinal
    shr {REG_DIRECTION}, 3
    mov rsi, {REG_DIRECTION}
    shr {REG_DIRECTION}, 16
    mov rdi, {REG_DIRECTION}
    neg si
    neg di
    movzx {REG_DIRECTION}, si
    shl {REG_DIRECTION}, 16
    movzx rdi, di
    or {REG_DIRECTION}, rdi
    shl {REG_DIRECTION}, 3
    or {REG_DIRECTION}, 4
    ret
reflect_is_cardinal:
    add {REG_DIRECTION}, 2
    and {REG_DIRECTION}, 3
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
{nexti}

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

get_line_char:
    # put (line, char) in (rax, rdx)
    # clobbers rcx
    mov rax, r14
    sub rax, OFFSET program_start
    mov rcx, 10
    xor rdx, rdx
    div rcx

    # get line and char indeces: (rax / width, rax % width)
    mov rcx, {width + 4}
    xor rdx, rdx
    div rcx
    ret

set_line_char:
    # set (line, char) to (rdi, rsi)
    # clobbers rax
    mov rax, rdi
    imul rax, {width + 4}
    add rax, rsi
    imul rax, 10
    add rax, OFFSET program_start
    add rax, 5
    mov r14, rax
    ret

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
    test {REG_DIRECTION}, 4
    jnz update_line_char_not_cardinal
    dec rdi
    cmp rdi, -1
    jne line_char_updated
    mov rdi, {height - 1}
    jmp line_char_updated
update_line_char_not_cardinal:
    push rsi
    push rdi
    mov rax, {REG_DIRECTION}
    shr rax, 3
    mov rsi, rax # dx
    shr rax, 16
    mov rdi, rax # dy
    movsx rsi, si
    movsx rdi, di
    pop rax
    pop rdx
    add rdi, rax # y
    add rsi, rdx # x

    mov rax, rdi
    cqo
    mov rcx, {height}
    idiv rcx
    mov rdi, rdx
    test rdx, rdx
    jge update_scale_width
    add rdi, rcx

update_scale_width:

    mov rax, rsi
    cqo
    mov rcx, {width}
    idiv rcx
    mov rsi, rdx
    test rdx, rdx
    jge update_pos_scaled
    add rdi, rcx

update_pos_scaled:
    call set_line_char
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
    push 0 # signal bottom of stack stack
    mov rbp, rsp
    push 0 # filler

    # reserve {STACK_ZERO_SIZE} zero bytes on the stack
    sub rsp, {STACK_ZERO_SIZE}
    lea rdi, [rsp]
    mov rcx, {STACK_ZERO_SIZE}
    xor al, al
    rep stosb

    xor {REG_DIRECTION}, {REG_DIRECTION}
    xor r8, r8 # g/p offset

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
