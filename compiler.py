#!/usr/bin/env python3
from argparse import ArgumentParser
from pathlib import Path
import subprocess
import struct

REG_DIRECTION = "r12"
REG_RET_ADDR = "r14"
WIDTH = 80
HEIGHT = 25

RED = "\033[31m"
YELLOW='\033[33m'
RESET = "\033[0m"

defined_instructions = {}

instruction_names = {}


def define_instruction(char):
    def decorator(f):
        defined_instructions[char] = f()
        instruction_names[char] = f.__name__

    return decorator


for d in "0123456789":
    defined_instructions[d] = f"push {d}"
    instruction_names[d] = f"integer{d}"


@define_instruction("+")
def add():
    return """
    pop rdi
    pop rsi
    add rsi, rdi
    push rsi
    """


@define_instruction("-")
def subtract():
    return """
    pop rdi
    pop rsi
    sub rsi, rdi
    push rsi
    """


@define_instruction("*")
def multiply():
    return """
    pop rdi
    pop rsi
    imul rsi, rdi
    push rsi
    """


@define_instruction("#")
def skip():
    return f"""
    mov rdx, [direction_deltas + {REG_DIRECTION}*8]
    shl rdx, 1
    sub r14, 5
    add r14, rdx
    """


@define_instruction("/")
def divide():
    return """
    pop rdi
    pop rsi
    test rdi, rdi
    jz div_zero
    mov rax, rsi
    cqo
    idiv rdi
    push rax
    jmp div_done
div_zero:
    push 0
div_done:
    """


@define_instruction("%")
def modulo():
    return """
    pop rdi
    pop rsi
    test rdi, rdi
    jz mod_zero
    mov rax, rsi
    cqo
    idiv rdi
    push rdx
    jmp mod_done
mod_zero:
    push 0         
mod_done:
    """


@define_instruction("!")
def logical_not():
    return """
    pop rax
    test rax, rax
    setz al
    movzx rax, al
    push rax
    """


@define_instruction("`")
def greater_than():
    return """
    pop rdi
    pop rsi
    cmp rsi, rdi
    setg al
    movzx rax, al
    push rax
    """


@define_instruction(".")
def write_int():
    return """
    pop rsi
    mov r13, rsp
    and rsp, 0xfffffffffffffff0
    lea rdi, format
    xor eax, eax
    call printf
    mov rsp, r13
    """


@define_instruction(",")
def write_char():
    return """
    lea rsi, [rsp]
    push r14
    push r12
    mov rax, 1
    mov rdi, 1
    mov rdx, 1
    syscall
    pop r12
    pop r14
    pop rax
    """


@define_instruction("~")
def get_char():
    return """
    push 0
    lea rsi, [rsp]       
    push r14             
    push r12
    mov rax, 0           
    mov rdi, 0           
    mov rdx, 1           
    syscall
    pop r12
    pop r14
    """


@define_instruction(">")
def right():
    return f"""
    mov {REG_DIRECTION}, 0
    """


@define_instruction("<")
def left():
    return f"""
    mov {REG_DIRECTION}, 1
    """


@define_instruction("v")
def down():
    return f"""
    mov {REG_DIRECTION}, 2
    """


@define_instruction("^")
def up():
    return f"""
    mov {REG_DIRECTION}, 3
    """


@define_instruction("_")
def horizontal_if():
    return f"""
    pop rax
    test rax, rax
    jz horizontal_if_false
    mov {REG_DIRECTION}, 1  
    jmp horizontal_if_done
horizontal_if_false:
    mov {REG_DIRECTION}, 0  
horizontal_if_done:
    """


@define_instruction("|")
def vertical_if():
    return f"""
    pop rax
    test rax, rax
    jz vertical_if_false
    mov {REG_DIRECTION}, 3  
    jmp vertical_if_done
vertical_if_false:
    mov {REG_DIRECTION}, 2  
vertical_if_done:
    """


@define_instruction(":")
def duplicate():
    return """
    pop rax
    push rax
    push rax
    """


@define_instruction("\\")
def swap():
    return """
    pop rax
    pop rbx
    push rax
    push rbx
    """


@define_instruction("$")
def pop_discard():
    return """
    pop rax
    """


@define_instruction("@")
def exit():
    return f"""
    mov rax, 60
    mov rdi, 0
    syscall
    """


@define_instruction("g")
def get():
    return f"""
    pop rax # y
    pop rbx # x
    imul rax, {WIDTH + 2}
    add rax, rbx
    xor rbx, rbx
    mov bl, byte ptr [funge_space + rax]
    push rbx
    """


@define_instruction("p")
def put():
    return f"""
    pop rax # y
    pop rbx # x
    pop rdx # value
    movzx rdx, dl
    imul rax, {WIDTH + 2}
    mov rsi, rax
    
    # modify funge space
    add rax, rbx
    mov byte ptr [funge_space + rax], dl

    # modify instruction
    # get function address
    mov r9, qword ptr [instruction_lut + rdx * 8]
    
    add rsi, rbx
    imul rsi, 10
    lea rcx, [program_start + rsi]

    lea r11, [rcx + 5]
    sub r9, r11

    mov byte ptr [rcx], 0xe8
    mov dword ptr [rcx + 1], r9d
    """


@define_instruction('"')
def string_mode():
    return f"""
string_mode_loop:
    # r14 += direction_deltas[REG_DIRECTION]
    mov rdx, [direction_deltas + {REG_DIRECTION}*8]
    add r14, rdx

    # Compute cell index: (r14 - program_start) / 5
    mov rax, r14
    sub rax, OFFSET program_start
    mov rcx, 10
    cqo
    idiv rcx

    # Load character from funge_space[rax]
    mov al, byte ptr [funge_space + rax]

    # If '"', end string mode
    cmp al, '"'
    je string_mode_end

    # Otherwise, push the character value
    movzx rdx, al
    push rdx

    # Continue loop
    jmp string_mode_loop

string_mode_end:
    """


@define_instruction(chr(255))
def nop():
    return f""


def parse_befunge(source: str):
    if "\t" in source:
        print(f"{YELLOW}WARNING:{RESET} tab found in source")

    lines = source.splitlines()
    lines = lines[:HEIGHT]
    result = [list(line[:WIDTH].ljust(WIDTH)) for line in lines]
    result.extend([[" "] * WIDTH] * (HEIGHT - len(result)))
    return result


def compile_befunge(befunge: list[list[str]]):
    instruction_functions = ""
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

    for i in range(-1, HEIGHT + 1):
        for j in range(-1, WIDTH + 1):
            if (i, j) == (0, 0):
                code_space += "program_start:"
            if i == -1:
                name = "top_edge"
            elif i == HEIGHT:
                name = "bottom_edge"
            elif j == -1:
                name = "left_edge"
            elif j == WIDTH:
                name = "right_edge"
            else:
                name = instruction_names.get(befunge[i][j])
                if name:
                    print(f"{RESET}{befunge[i][j]}", end="")
                else:
                    print(f"{RED}{befunge[i][j]}{RESET}", end="")
            if name:
                code_space += f"call {name}\n"
            else:
                code_space += f"nop\n" * 5
            code_space += f"call nexti\n"
        print()

    funge_space = ""
    for y, row in enumerate(befunge):
        for x, instruction in enumerate(row):
            funge_space += f".byte {ord(instruction)}\n"
        funge_space += f".byte 0\n"
        funge_space += f".byte 0\n"

    instruction_lut = ""
    for i in range(256):
        function_name = instruction_names.get(chr(i), "nop")
        instruction_lut += f".quad {function_name}\n"

    instr_bytes = 10

    return f"""
    .intel_syntax noprefix
    .extern printf

    .file "compiled.s"
    .globl main

    .data

    direction_deltas:
        # used for quotes
        .quad 10
        .quad -10
        .quad {(WIDTH + 2) * 10}
        .quad {-(WIDTH + 2) * 10}

    funge_space:
    {funge_space}

    .section .rodata
    format:
        .string "%d\\n"

    instruction_lut:
    {instruction_lut}

    .text

    {instruction_functions}

    left_edge:
        pop r14
        sub r14, 5
        add r14, {WIDTH * 10}
        push r14
        ret

    right_edge:
        pop r14
        sub r14, 5
        sub r14, {WIDTH * 10}
        push r14
        ret


    top_edge:
        pop r14
        sub r14, 5
        add r14, {((WIDTH + 2) * HEIGHT) * 10}
        push r14
        ret

    bottom_edge:
        pop r14
        sub r14, 5
        sub r14, {((WIDTH + 2) * HEIGHT) * 10}
        push r14
        ret

    nexti:
        pop r14
        mov rdx, [direction_deltas + {REG_DIRECTION}*8]
        sub r14, 10
        add r14, rdx
        push r14
    nexti_exit:
        ret

    main:
    # Reserve 0x1000 zero bytes on the stack
    sub rsp, 0x1000
    lea rdi, [rsp]
    mov rcx, 0x1000
    xor al, al
    rep stosb

    xor {REG_DIRECTION}, {REG_DIRECTION}

    jmp program_start

    {code_space}
    """


def main():
    parser = ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()

    parsed = parse_befunge(args.source.read_text("latin-1"))
    compiled = compile_befunge(parsed)
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
