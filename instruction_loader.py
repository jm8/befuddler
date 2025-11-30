REG_DIRECTION = "r12"
REG_RET_ADDR = "r14"

DIR_RIGHT = 0
DIR_DOWN = 1
DIR_LEFT = 2
DIR_UP = 3

def define_instruction(char):
    def decorator(f):
        f._instruction_name = char
        return f
    return decorator


def b98(f):
    f._b98 = True
    return f


def b93(f):
    f._b93 = True
    return f


class InstructionLoader:
    def __init__(self, width: int, height: int, b98: bool):
        self.width = width
        self.height = height
        self.b98 = b98

        self.defined_instructions = {}
        self.instruction_names = {}

        self.integer_instructions()
        self.general_instructions()


    def integer_instructions(self):
        for d in ("0123456789abcdef" if self.b98 else "0123456789"):
            self.defined_instructions[d] = f"""
            push 0x{d}
            """
            self.instruction_names[d] = f"integer_{d}"


    def general_instructions(self):
        for name in dir(self):
            attr = getattr(self, name)
            if hasattr(attr, "_instruction_name"):
                include = True
                if getattr(attr, "_b98", False) and not b98:
                    include = False
                elif getattr(attr, "_b93", False) and b98:
                    include = False

                if include:
                    self.instruction_names[attr._instruction_name] = name
                    self.defined_instructions[attr._instruction_name] = attr()

          
    @define_instruction("+")
    def add(self):
        return """
    pop rdi
    pop rsi
    add rsi, rdi
    push rsi
    """


    @define_instruction("-")
    def subtract(self):
        return """
    pop rdi
    pop rsi
    sub rsi, rdi
    push rsi
    """


    @define_instruction("*")
    def multiply(self):
        return """
    pop rdi
    pop rsi
    imul rsi, rdi
    push rsi
    """


    @define_instruction("#")
    def skip(self):
        return f"""
    mov rdx, [direction_deltas + {REG_DIRECTION}*8]
    shl rdx, 1
    sub r14, 5
    add r14, rdx
    """


    @define_instruction("/")
    def divide(self):
        return f"""
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
    def modulo(self):
        return f"""
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
    def logical_not(self):
        return f"""
    pop rax
    test rax, rax
    setz al
    movzx rax, al
    push rax
    """


    @define_instruction("`")
    def greater_than(self):
        return f"""
    pop rdi
    pop rsi
    cmp rsi, rdi
    setg al
    movzx rax, al
    push rax
    """


    @define_instruction(".")
    def write_int(self):
        return f"""
    pop rax

    push r14
    push r12
    mov r13, rsp
    mov rsi, 1
    dec rsp
    mov byte ptr [rsp], ' '

    test rax, rax
    jnz not_zero
    dec rsp
    inc rsi
    mov byte ptr [rsp], '0'
    jmp number_built
not_zero:
    mov rcx, 10
    cqo
    idiv rcx

    test rax, rax
    jz last_digit
    test rdx, rdx
    jge digit_positive
    neg rdx
digit_positive:
    dec rsp
    inc rsi
    add rdx, '0'
    mov byte ptr [rsp], dl
    jmp not_zero

last_digit:
    test rdx, rdx
    jge last_digit_positive
    neg rdx
    dec rsp
    inc rsi
    add rdx, '0'
    mov byte ptr [rsp], dl
    dec rsp
    inc rsi
    mov byte ptr [rsp], '-'
    jmp number_built

last_digit_positive:
    dec rsp
    inc rsi
    add rdx, '0'
    mov byte ptr [rsp], dl

number_built:
    mov rax, 1
    mov rdi, 1
    mov rdx, rsi
    lea rsi, [rsp]
    syscall

    mov rsp, r13
    pop r12
    pop r14
    """


    @define_instruction(",")
    def write_char(self):
        return f"""
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
    def get_char(self):
        return f"""
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
    def right(self):
        return f"""
    mov {REG_DIRECTION}, {DIR_RIGHT}
    """


    @define_instruction("<")
    def left(self):
        return f"""
    mov {REG_DIRECTION}, {DIR_LEFT}
    """


    @define_instruction("v")
    def down(self):
        return f"""
    mov {REG_DIRECTION}, {DIR_DOWN}
    """


    @define_instruction("^")
    def up(self):
        return f"""
    mov {REG_DIRECTION}, {DIR_UP}
    """


    @define_instruction("_")
    def horizontal_if(self):
        return f"""
    pop rax
    test rax, rax
    jz horizontal_if_false
    mov {REG_DIRECTION}, {DIR_LEFT}
    jmp horizontal_if_done
horizontal_if_false:
    mov {REG_DIRECTION}, {DIR_RIGHT}
horizontal_if_done:
    """


    @define_instruction("|")
    def vertical_if(self):
        return f"""
    pop rax
    test rax, rax
    jz vertical_if_false
    mov {REG_DIRECTION}, {DIR_UP}
    jmp vertical_if_done
vertical_if_false:
    mov {REG_DIRECTION}, {DIR_DOWN}
vertical_if_done:
    """


    @define_instruction(":")
    def duplicate(self):
        return """
    pop rax
    push rax
    push rax
    """


    @define_instruction("\\")
    def swap(self):
        return """
    pop rax
    pop rbx
    push rax
    push rbx
    """


    @define_instruction("$")
    def pop_discard(self):
        return """
    pop rax
    """


    @define_instruction("@")
    def exit(self):
        return f"""
    mov rax, 60
    mov rdi, 0
    syscall
    """


    @define_instruction("g")
    @b93
    def get(self):
        return f"""
    pop rsi # y
    pop rdi # x
    call in_range
    test rax, rax
    jne get_in_range

    lea rdi, error_bad_read
    call print_error_and_exit

get_in_range:
    imul rsi, {self.width + 4}
    add rsi, rdi
    xor rbx, rbx
    movsx rbx, byte ptr [funge_space + rsi]
    push rbx
    """


    @define_instruction("g")
    @b98
    def get(self):
        return f"""
    pop rsi # y
    pop rdi # x
    call in_range
    test rax, rax
    jne get_in_range

    add {REG_DIRECTION}, 2
    and {REG_DIRECTION}, 3
    jmp skip_g

get_in_range:
    imul rsi, {self.width + 4}
    add rsi, rdi
    xor rbx, rbx
    movsx rbx, byte ptr [funge_space + rsi]
    push rbx
skip_g:
    """


    @define_instruction("p")
    @b93
    def put(self):
        return f"""
    pop rsi # y
    pop rdi # x

    call in_range
    test rax, rax
    jne put_in_range

    lea rdi, error_bad_write
    call print_error_and_exit

put_in_range:
    pop rdx # value
    movzx rdx, dl
    imul rsi, {self.width + 4}
    mov rax, rsi

    # modify funge space
    add rsi, rdi
    mov byte ptr [funge_space + rsi], dl

    # modify instruction
    # get function address
    mov r9, qword ptr [instruction_lut + rdx * 8]

    add rax, rdi
    imul rax, 10
    lea rcx, [program_start + rax]

    lea r15, [rcx + 5]
    sub r9, r15

    mov byte ptr [rcx], 0xe8
    mov dword ptr [rcx + 1], r9d
    """


    @define_instruction("p")
    @b98
    def put(self):
        return f"""
    pop rsi # y
    pop rdi # x

    call in_range
    test rax, rax
    jne put_in_range

    add {REG_DIRECTION}, 2
    and {REG_DIRECTION}, 3
    jmp skip_p

put_in_range:
    pop rdx # value
    movzx rdx, dl
    imul rsi, {self.width + 4}
    mov rax, rsi

    # modify funge space
    add rsi, rdi
    mov byte ptr [funge_space + rsi], dl

    # modify instruction
    # get function address
    mov r9, qword ptr [instruction_lut + rdx * 8]

    add rax, rdi
    imul rax, 10
    lea rcx, [program_start + rax]

    lea r15, [rcx + 5]
    sub r9, r15

    mov byte ptr [rcx], 0xe8
    mov dword ptr [rcx + 1], r9d
skip_p:
    """


    @define_instruction('"')
    def string_mode(self):
        return f"""
    # Compute cell index: (r14 - program_start) / 10
    mov rax, r14
    sub rax, OFFSET program_start
    mov rcx, 10
    xor rdx, rdx
    div rcx

    # Get line and char indeces: (rax / self.width, rax % self.width)
    mov rcx, {self.width + 4}
    xor rdx, rdx
    div rcx

    mov rdi, rax # line
    mov rsi, rdx # char

string_mode_loop:
    call update_line_char

    # Set rax to funge space index
    mov rax, rdi
    mov rcx, {self.width + 4}
    mul rcx
    add rax, rsi

    # Load character from funge_space[rax]
    mov cl, byte ptr [funge_space + rax]

    # If '"', end string mode
    cmp cl, '"'
    je string_mode_end

    # Otherwise, push the character value
    movsx rdx, cl
    push rdx

    # Continue loop
    jmp string_mode_loop

string_mode_end:
    # Jump to correct position
    mov rax, rdi
    imul rax, {self.width + 4}
    add rax, rsi
    imul rax, 10
    add rax, OFFSET program_start
    add rax, 5
    mov r14, rax
    """


    @define_instruction("?")
    def go_away(self):
        return f"""
    mov rax, qword ptr [rand_seed]
    mov rdx, 1103515245
    mul rdx
    add rax, 12345
    mov qword ptr [rand_seed], rax
    shr rax, 32
    and rax, 3
    mov {REG_DIRECTION}, rax
    """


    @define_instruction("&")
    def read_int(self):
        return """
    push r14
    push r12
    push 0

skip_whitespace:
    mov rax, 0
    mov rdi, 0
    lea rsi, [rsp]
    mov rdx, 1
    syscall

    cmp byte ptr [rsp], ' '
    je skip_whitespace
    cmp byte ptr [rsp], '\\n'
    je skip_whitespace
    cmp byte ptr [rsp], '\\t'
    je skip_whitespace

    xor r13, r13
    xor r15, r15
    cmp byte ptr [rsp], '-'
    jne read_int_loop

    inc r15 # is negative
    mov rax, 0
    mov rdi, 0
    lea rsi, [rsp]
    mov rdx, 1
    syscall

read_int_loop:
    sub byte ptr [rsp], '0'
    cmp byte ptr [rsp], 9
    ja int_reading_complete

    mov rax, r13
    mov rcx, 10
    imul rcx
    mov r13, rax
    movzx rcx, byte ptr [rsp]
    add r13, rcx

    mov rax, 0
    mov rdi, 0
    lea rsi, [rsp]
    mov rdx, 1
    syscall

    jmp read_int_loop
int_reading_complete:
    test r15, r15
    jz int_not_negative
    neg r13
int_not_negative:
    pop r12
    pop r12
    pop r14
    push r13
    """


    @define_instruction("r")
    @b98
    def reflect(self):
        return f"""
    add {REG_DIRECTION}, 2
    and {REG_DIRECTION}, 3
    """


    @define_instruction("[")
    @b98
    def turn_left(self):
        return f"""
    dec {REG_DIRECTION}
    and {REG_DIRECTION}, 3
    """


    @define_instruction("]")
    @b98
    def turn_right(self):
        return f"""
    inc {REG_DIRECTION}
    and {REG_DIRECTION}, 3
    """


    @define_instruction("(")
    @b98
    def load_semantics(self):
        return f"""
    pop rdi
load_semantic:
    test rdi, rdi
    # always fail
    jz semantic_load_fail
    pop rsi
    dec rdi
    jmp load_semantic
semantic_load_fail:
    add {REG_DIRECTION}, 2
    and {REG_DIRECTION}, 3
    """


    @define_instruction(")")
    @b98
    def unload_semantics(self):
        return f"""
    pop rdi
unload_semantic:
    test rdi, rdi
    # always fail
    jz semantic_unload_fail
    pop rsi
    dec rdi
    jmp unload_semantic
semantic_unload_fail:
    add {REG_DIRECTION}, 2
    and {REG_DIRECTION}, 3
    """


    @define_instruction("q")
    @b98
    def exit_with_code(self):
        return f"""
    mov rax, 60
    pop rdi
    syscall
    """


    @define_instruction("w")
    @b98
    def compare(self):
        return f"""
    pop rdi
    pop rsi
    xor rax, rax
    cmp rsi, rdi
    jz dont_turn
    jg greater
    dec rax
    jmp dont_turn
greater:
    inc rax
dont_turn:
    add {REG_DIRECTION}, rax
    and {REG_DIRECTION}, 3
    """


    @define_instruction(";")
    @b98
    def jump_over(self):
        return f"""
    # Compute cell index: (r14 - program_start) / 10
    mov rax, r14
    sub rax, OFFSET program_start
    mov rcx, 10
    xor rdx, rdx
    div rcx

    # Get line and char indeces: (rax / self.width, rax % self.width)
    mov rcx, {self.width + 4}
    xor rdx, rdx
    div rcx

    mov rdi, rax # line
    mov rsi, rdx # char

jump_over_loop:
    call update_line_char

    # Set rax to funge space index
    mov rax, rdi
    mov rcx, {self.width + 4}
    mul rcx
    add rax, rsi

    # Load character from funge_space[rax]
    mov cl, byte ptr [funge_space + rax]

    # If ';', end jump over
    cmp cl, ';'
    je jump_over_end

    # Continue loop
    jmp jump_over_loop

jump_over_end:
    # Jump to correct position
    mov rax, rdi
    imul rax, {self.width + 4}
    add rax, rsi
    imul rax, 10
    add rax, OFFSET program_start
    add rax, 5
    mov r14, rax
    """

    @define_instruction("z")
    @b98
    def z_nop(self):
        return f""


    @define_instruction(" ")
    @b98
    def space_nop(self):
        return f""


    @define_instruction("k")
    @b98
    def iterate(self):
        return f"""
    pop r10 # number of times to iterate
    xor r8, r8 # not skipping flag
    test r10, r10
    jnz run_iterate
    # Special case, zero acts as skip
    mov rdx, [direction_deltas + {REG_DIRECTION}*8]
    shl rdx, 1
    sub r14, 5
    add r14, rdx
    jmp end_iterate

run_iterate:
    mov rax, r14
    sub rax, OFFSET program_start
    mov rcx, 10
    xor rdx, rdx
    div rcx

    # Get line and char indeces: (rax / self.width, rax % self.width)
    mov rcx, {self.width + 4}
    xor rdx, rdx
    div rcx

    mov rdi, rax # line
    mov rsi, rdx # char

iterate_bad_char_or_skips:
    call update_line_char

    # Set rax to funge space index
    mov rax, rdi
    mov rcx, {self.width + 4}
    mul rcx
    add rax, rsi

    test r8, r8
    jnz keep_skipping

    # Load character from funge_space[rax]
    mov cl, byte ptr [funge_space + rax]
    cmp cl, ' '
    je iterate_bad_char_or_skips
    cmp cl, ';'
    je iterate_bad_char_or_skips

    cmp cl, '#'
    jne normal_iterate
    inc r8 # set skipping flag
    jmp run_iterate

keep_skipping:
    dec r10
    jnz iterate_bad_char_or_skips

    # Jump to correct position
    mov rax, rdi
    imul rax, {self.width + 4}
    add rax, rsi
    imul rax, 10
    add rax, OFFSET program_start
    add rax, 5
    mov r14, rax

    jmp end_iterate
normal_iterate:
    movzx rcx, cl

    # NOTE - this section assumes r10, r8, and r11
    # are untouched by whatever function this thing
    # calls...
    mov r8, qword ptr [instruction_lut + rcx * 8]

    mov r11, r14
iterate_again:
    call r8
    dec r10
    jnz iterate_again

    mov r14, r11

end_iterate:
    """


    @define_instruction("n")
    @b98
    def clear_stack(self):
        return f"""
        mov rsp, rbp

        # Reserve 0x1000 zero bytes on the stack
        sub rsp, 0x1000
        lea rdi, [rsp]
        mov rcx, 0x1000
        xor al, al
        rep stosb
    """
