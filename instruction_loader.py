from collections import defaultdict

REG_DIRECTION = "r12"
REG_RET_ADDR = "r14"

DIR_RIGHT = 0
DIR_DOWN = 1
DIR_LEFT = 2
DIR_UP = 3

MAX_FINGERPRINT_LEN = 8
MAX_INPUT_LEN = 32

STACK_ZERO_SIZE = 0x1000


def define_instruction(char):
    def decorator(f):
        f._instruction_name = ord(char)
        return f
    return decorator


def fingerprint(id):
    def decorator(f):
        f._fingerprint_id = id
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

        self.fingerprints = defaultdict(list)

        self.integer_instructions()
        self.general_instructions()
        if b98:
            self.build_semantics()
            self.set_fingerprints()


    def integer_instructions(self):
        for d in (b"0123456789abcdef" if self.b98 else b"0123456789"):
            self.defined_instructions[d] = f"""
    push 0x{chr(d)}
"""
            self.instruction_names[d] = f"integer_{chr(d)}"


    def build_semantics(self):
        for i in range(26):
            c = ord('A') + i
            self.defined_instructions[c] = f"""
    push r14
    mov rdx, {i}
    jmp [semantic_lut + rdx * 8]
"""
            self.instruction_names[c] = f"semantic_{c}"


    def general_instructions(self):
        for name in dir(self):
            attr = getattr(self, name)
            if hasattr(attr, "_instruction_name"):
                include = True
                if hasattr(attr, "_fingerprint_id"):
                    include = False
                if getattr(attr, "_b98", False) and not self.b98:
                    include = False
                if getattr(attr, "_b93", False) and self.b98:
                    include = False

                if include:
                    self.instruction_names[attr._instruction_name] = name
                    self.defined_instructions[attr._instruction_name] = attr()


    def set_fingerprints(self):
        for name in dir(self):
            attr = getattr(self, name)
            if hasattr(attr, "_fingerprint_id"):
                self.fingerprints[attr._fingerprint_id].append(
                    (attr._instruction_name, name, attr())
                )

          
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
    @b93
    def skip_b93(self):
        return f"""
    mov rdx, [direction_deltas + {REG_DIRECTION}*8]
    shl rdx, 1
    sub r14, 5
    add r14, rdx
    """


    @define_instruction("#")
    @b98
    def skip_b98(self):
        return f"""
handle_skip_b98:
    test {REG_DIRECTION}, 4
    jz hashtag_is_cardinal
    mov rax, {REG_DIRECTION}
    shr rax, 3
    mov rsi, rax # dx
    shr rax, 16
    mov rdi, rax # dy
    movsx rsi, si
    movsx rdi, di
    call get_line_char
    shl rsi
    shl rdi
    add rdi, rax # y
    add rsi, rdx # x

    mov rax, rdi
    cqo
    mov rcx, {self.height}
    idiv rcx
    mov rdi, rdx
    test rdx, rdx
    jge skip_b98_scale_width
    add rdi, rcx

skip_b98_scale_width:
    mov rax, rsi
    cqo
    mov rcx, {self.width}
    idiv rcx
    mov rsi, rdx
    test rdx, rdx
    jge skip_b98_pos_scaled
    add rsi, rcx

skip_b98_pos_scaled:
    call set_line_char

    jmp hashtag_not_cardinal
hashtag_is_cardinal:
    mov rdx, [direction_deltas + {REG_DIRECTION}*8]
hashtag_not_cardinal:
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
    push r11
    syscall
    pop r11

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
    push r11
    mov rax, 1
    mov rdi, 1
    mov rdx, 1
    syscall
    pop r11
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
    push r11
    mov rax, 0
    mov rdi, 0
    mov rdx, 1
    syscall
    pop r11
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
    def get_b93(self):
        return f"""
    pop rsi # y
    pop rdi # x
    mov r9, r8
    shr r9, 32
    add rsi, r9
    mov r9d, r8d
    add rdi, r9

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
    def get_b98(self):
        return f"""
    pop rsi # y
    pop rdi # x
    mov r9, r8
    shr r9, 32
    add rsi, r9
    mov r9d, r8d
    add rdi, r9

    call in_range
    test rax, rax
    jne get_in_range

    call reflect
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
    def put_b93(self):
        return f"""
    pop rsi # y
    pop rdi # x
    mov r9, r8
    shr r9, 32
    add rsi, r9
    mov r9d, r8d
    add rdi, r9

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
    lea rcx, [code_space_start + rax]

    lea r15, [rcx + 5]
    sub r9, r15

    mov byte ptr [rcx], 0xe8
    mov dword ptr [rcx + 1], r9d
    """


    @define_instruction("p")
    @b98
    def put_b98(self):
        return f"""
    pop rsi # y
    pop rdi # x
    mov r9, r8
    shr r9, 32
    add rsi, r9
    mov r9d, r8d
    add rdi, r9

    call in_range
    test rax, rax
    jne put_in_range

    call reflect
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
    lea rcx, [code_space_start + rax]

    lea r15, [rcx + 5]
    sub r9, r15

    mov byte ptr [rcx], 0xe8
    mov dword ptr [rcx + 1], r9d
skip_p:
    """


    @define_instruction('"')
    @b93
    def string_mode_b93(self):
        return f"""
    # compute cell index: (r14 - code_space_start) / 10
    call get_line_char

    mov rdi, rax # line
    mov rsi, rdx # char

string_mode_loop:
    call update_line_char

    # set rax to funge space index
    mov rax, rdi
    mov rcx, {self.width + 4}
    mul rcx
    add rax, rsi

    # load character from funge_space[rax]
    mov cl, byte ptr [funge_space + rax]

    # if '"', end string mode
    cmp cl, '"'
    je string_mode_end

    # otherwise, push the character value
    movsx rdx, cl
    push rdx

    # continue loop
    jmp string_mode_loop

string_mode_end:
    # jump to correct position
    call set_line_char
    """


    @define_instruction('"')
    @b98
    def string_mode_b98(self):
        return f"""
    # compute cell index: (r14 - code_space_start) / 10
    call get_line_char

    mov rdi, rax # line
    mov rsi, rdx # char

    xor r9, r9 # space last seen

string_mode_loop:
    call update_line_char

    # set rax to funge space index
    mov rax, rdi
    mov rcx, {self.width + 4}
    mul rcx
    add rax, rsi

    # load character from funge_space[rax]
    mov cl, byte ptr [funge_space + rax]

    # if '"', end string mode
    cmp cl, '"'
    je string_mode_end

    cmp cl, ' '
    je space_seen
    xor r9, r9
    # otherwise, push the character value
string_mode_push_char:
    movsx rdx, cl
    push rdx
    jmp string_mode_loop
space_seen:
    test r9, r9
    jnz string_mode_loop
    inc r9
    jmp string_mode_push_char
string_mode_end:
    # jump to correct position
    call set_line_char
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
    push r11
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
    pop r11
    pop r11
    pop r12
    pop r14
    push r13
    """


    @define_instruction("r")
    @b98
    def pure_reflect(self):
        return f"""
    call reflect
    """


    @define_instruction("[")
    @b98
    def turn_left(self):
        return f"""
    test {REG_DIRECTION}, 4
    jz left_is_cardinal
    shr {REG_DIRECTION}, 3
    mov rsi, {REG_DIRECTION}
    shr {REG_DIRECTION}, 16
    mov rdi, {REG_DIRECTION}
    neg si
    movzx {REG_DIRECTION}, di
    shl {REG_DIRECTION}, 16
    movzx rsi, si
    or {REG_DIRECTION}, rsi
    shl {REG_DIRECTION}, 3
    or {REG_DIRECTION}, 4
    jmp turn_left_end
left_is_cardinal:
    dec {REG_DIRECTION}
    and {REG_DIRECTION}, 3
turn_left_end:
    """


    @define_instruction("]")
    @b98
    def turn_right(self):
        return f"""
    test {REG_DIRECTION}, 4
    jz right_is_cardinal
right_not_cardinal:
    shr {REG_DIRECTION}, 3
    mov rsi, {REG_DIRECTION}
    shr {REG_DIRECTION}, 16
    mov rdi, {REG_DIRECTION}
    neg di
    movzx {REG_DIRECTION}, di
    shl {REG_DIRECTION}, 16
    movzx rsi, si
    or {REG_DIRECTION}, rsi
    shl {REG_DIRECTION}, 3
    or {REG_DIRECTION}, 4
    jmp turn_right_end
right_is_cardinal:
    inc {REG_DIRECTION}
    and {REG_DIRECTION}, 3
turn_right_end:
    """


    @define_instruction("(")
    @b98
    def load_semantics(self):
        return f"""
    pop rdi
    test rdi, rdi
    jl load_semantic_fail
    xor rdx, rdx # index
load_semantic:
    cmp rdi, rdx
    je semantic_in_buf
    pop rsi
    cmp rdx, {MAX_FINGERPRINT_LEN}
    jg wrote_max_semantic_len
    je null_terminate_semantic
    movzx rsi, sil
    mov byte ptr [input_buf + rdx], sil
    jmp wrote_max_semantic_len
null_terminate_semantic:
    mov byte ptr [input_buf + rdx], 0
wrote_max_semantic_len:
    inc rdx
    jmp load_semantic
semantic_in_buf:
    xor rdi, rdi # fingerprint_table idx
search_fingerprint_table:
    shl rdi, 1
    lea rsi, [fingerprint_table + rdi * 8]
    shr rdi, 1
    cmp byte ptr [rsi], 0
    je load_semantic_fail
    xor rdx, rdx # char idx

compare_fingerprint_ids:
    mov cl, byte ptr [input_buf + rdx]
    mov r9b, byte ptr [rsi]
    cmp cl, r9b
    jne load_semantic_match_not_found
    test cl, cl
    jz load_semantic_match_found

    inc rdx
    inc rsi
    jmp compare_fingerprint_ids

load_semantic_match_not_found:
    inc rdi
    jmp search_fingerprint_table

load_semantic_match_found:
    # load section into rsi
    shl rdi, 1
    lea rsi, [fingerprint_table + rdi * 8]
    mov rsi, [rsi + 8]

    # process semantic section
keep_loading_semantic:
    mov rcx, qword ptr [rsi]
    cmp rcx, -1
    je load_semantic_end
    add rsi, 8
    mov rdi, [rsi]
    mov qword ptr [semantic_lut + rcx * 8], rdi
    add rsi, 8
    jmp keep_loading_semantic

load_semantic_fail:
    call reflect
load_semantic_end:
    """


    @define_instruction(")")
    @b98
    def unload_semantics(self):
        return f"""
    pop rdi
    test rdi, rdi
    jl unload_semantic_fail
unload_semantic:
    test rdi, rdi
    # always fail
    jz unload_semantic_fail
    pop rsi
    dec rdi
    jmp unload_semantic
unload_semantic_fail:
    call reflect
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
    test rax, rax
    jz compare_end
    test {REG_DIRECTION}, 4
    jnz right_not_cardinal
    inc {REG_DIRECTION}
    and {REG_DIRECTION}, 3
compare_end:
    """


    @define_instruction(";")
    @b98
    def jump_over(self):
        return f"""
    # compute cell index: (r14 - code_space_start) / 10
    call get_line_char

    mov rdi, rax # line
    mov rsi, rdx # char

jump_over_loop:
    call update_line_char

    # set rax to funge space index
    mov rax, rdi
    mov rcx, {self.width + 4}
    mul rcx
    add rax, rsi

    # load character from funge_space[rax]
    mov cl, byte ptr [funge_space + rax]

    # if ';', end jump over
    cmp cl, ';'
    je jump_over_end

    # continue loop
    jmp jump_over_loop

jump_over_end:
    # jump to correct position
    call set_line_char
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
    xor r9, r9 # not skipping flag
    test r10, r10
    jge k_valid_input
    call reflect
    jmp end_iterate
k_valid_input:
    jnz run_iterate
    # Special case, zero acts as skip
    jmp handle_skip_b98

run_iterate:
    call get_line_char

    mov rdi, rax # line
    mov rsi, rdx # char

iterate_bad_char_or_skips:
    call update_line_char

    # set rax to funge space index
    mov rax, rdi
    mov rcx, {self.width + 4}
    mul rcx
    add rax, rsi

    test r9, r9
    jnz keep_skipping

    # load character from funge_space[rax]
    mov cl, byte ptr [funge_space + rax]
    cmp cl, ' '
    je iterate_bad_char_or_skips
    cmp cl, ';'
    je iterate_bad_char_or_skips

    cmp cl, '#'
    jne normal_iterate
    inc r9 # set skipping flag
    jmp run_iterate

keep_skipping:
    dec r10
    jnz iterate_bad_char_or_skips

    # jump to correct position
    call set_line_char

    jmp end_iterate
normal_iterate:
    movzx rcx, cl

    # NOTE - this section assumes r10, r9, and r11
    # are untouched by whatever function this thing
    # calls...
    mov r9, qword ptr [instruction_lut + rcx * 8]

    mov r11, r14
iterate_again:
    call r9
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

    # reserve {STACK_ZERO_SIZE} zero bytes on the stack
    sub rsp, {STACK_ZERO_SIZE}
    lea rdi, [rsp]
    mov rcx, {STACK_ZERO_SIZE}
    xor al, al
    rep stosb
    """

    @define_instruction("'")
    @b98
    def push_char(self):
        return f"""
    # compute cell index: (r14 - code_space_start) / 10
    call get_line_char

    mov rdi, rax # line
    mov rsi, rdx # char

    call update_line_char

    # set rax to funge space index
    mov rax, rdi
    mov rcx, {self.width + 4}
    mul rcx
    add rax, rsi

    # load character from funge_space[rax]
    mov cl, byte ptr [funge_space + rax]

    # push the character value
    movsx rdx, cl
    push rdx

    # jump to correct position
    jmp handle_skip_b98
    """


    @define_instruction("s")
    @b98
    def store_char(self):
        return f"""
    # compute cell index: (r14 - code_space_start) / 10
    call get_line_char

    mov rdi, rax # line
    mov rsi, rdx # char

    call update_line_char

    # set rax to funge space index
    mov rax, rdi
    mov rcx, {self.width + 4}
    mul rcx
    add rax, rsi

    # modify funge space
    pop rdx # value
    movzx rdx, dl
    mov byte ptr [funge_space + rax], dl

    # jump to correct position
    jmp handle_skip_b98
    """


    @define_instruction("x")
    @b98
    def absolute_delta(self):
        return f"""
    pop rsi # y
    pop rdi # x
    test rdi, rdi
    jz delta_x_zero
    test rsi, rsi
    jnz non_cardinal_delta
    cmp rdi, 1
    jne delta_y_zero_x_not_1
    mov {REG_DIRECTION}, {DIR_RIGHT}
    jmp delta_set
delta_y_zero_x_not_1:
    cmp rdi, -1
    jne non_cardinal_delta
    mov {REG_DIRECTION}, {DIR_LEFT}
    jmp delta_set
delta_x_zero:
    cmp rsi, 1
    jne delta_x_zero_y_not_1
    mov {REG_DIRECTION}, {DIR_UP}
    jmp delta_set
delta_x_zero_y_not_1:
    cmp rsi, -1
    jne non_cardinal_delta
    mov {REG_DIRECTION}, {DIR_DOWN}
    jmp delta_set
non_cardinal_delta:
    movzx rsi, si
    movzx rdi, di
    mov {REG_DIRECTION}, rsi
    shl {REG_DIRECTION}, 16
    or {REG_DIRECTION}, rdi
    shl {REG_DIRECTION}, 3
    or {REG_DIRECTION}, 4
delta_set:
    """


    @define_instruction("j")
    @b98
    def jump(self):
        return f"""
    pop r10 # number of times to skip

    call get_line_char

    mov rdi, rax # line
    mov rsi, rdx # char

    test r10, r10
    jg jump_forwards_loop
    jz skip_jumping

    call reflect
jump_backwards_loop:
    call update_line_char
    inc r10
    jnz jump_backwards_loop
    call reflect
    jmp jumping_done

jump_forwards_loop:
    call update_line_char
    dec r10
    jnz jump_forwards_loop

jumping_done:
    # jump to correct position
    call set_line_char
skip_jumping:
    """


    @define_instruction("y")
    @b98
    def get_sys_info(self):
        return f"""

    # get stack size
    mov rsi, rbp
    sub rsi, rsp
    sub rsi, {STACK_ZERO_SIZE}
    sar rsi, 3
    test rsi, rsi
    jg y_stack_size_positive
    xor rsi, rsi
y_stack_size_positive:

    pop rdi
    cmp rdi, 20
    jle y_valid_input
    sub rdi, 20
y_get_to_cell:
    test rdi, rdi
    jz y_1_exclude
    pop rsi
    dec rdi
    jmp y_get_to_cell
y_valid_input:

    # 20. a series of strings, each terminated by a null, the series terminated by an additional null, containing the environment variables. (env)
    #         The format for each variable setting is NAME=VALUE.

    test rdi, rdi
    jle y_20_include
    cmp rdi, 20
    jne y_20_exclude
y_20_include:

    # TODO
    push 0

    # 19. a series of sequences of characters (strings), each terminated by a null, the series terminated by an additional double null, containing the command-line arguments. (env)
    #         This means any isolated argument can be a null string, but no two consecutive arguments may be null strings - a rather contrived scenario, null string arguments being rare in themselves.
    #         The first string is the name of the Funge source program being run.

y_20_exclude:
    test rdi, rdi
    jle y_19_include
    cmp rdi, 19
    jne y_19_exclude
y_19_include:

    # TODO
    push 0
    push 0

    # 18. size-of-stack-stack cells containing size of each stack, listed from TOSS to BOSS (ip)
    #         Stack sizes are pushed as if they were measured before y began pushing elements onto the stack.

y_19_exclude:
    test rdi, rdi
    jle y_18_include
    cmp rdi, 18
    jne y_18_exclude
y_18_include:

    # TODO
    push rsi

    # 17. 1 cell containing the total number of stacks currently in use by the IP (size of stack stack) (ip)

y_18_exclude:
    test rdi, rdi
    jle y_17_include
    cmp rdi, 17
    jne y_17_exclude
y_17_include:

    # TODO
    push 1

    # 16. 1 cell containing current (hour * 256 * 256) + (minute * 256) + (second) (env)

y_17_exclude:
    test rdi, rdi
    jle y_16_include
    cmp rdi, 15
    je y_16_include # exception: 16 pre-req for 15 (wont be pushed though)
    cmp rdi, 16
    jne y_16_exclude
y_16_include:

    mov rax, 0xc9
    mov rdi, 0
    push r14
    push r11
    syscall
    pop r11
    pop r14

    # rax: seconds since 1970-01-01 00:00:00 +0000 (UTC).

    mov rcx, 60
    xor rdx, rdx
    div rcx

    mov r9, rdx # r9 = (second)

    mov rcx, 60
    xor rdx, rdx
    div rcx

    shl rdx, 8
    add r9, rdx # r9 = (minute * 256) + (second)

    mov rcx, 24
    xor rdx, rdx
    div rcx

    shl rdx, 16
    add r9, rdx # r9 = (hour * 256 * 256) + (minute * 256) + (second)

    cmp rdi, 15
    je y_16_exclude
    push r9

    # 15. 1 cell containing current ((year - 1900) * 256 * 256) + (month * 256) + (day of month) (env)
    
y_16_exclude:
    test rdi, rdi
    jle y_15_include
    cmp rdi, 15
    jne y_15_exclude
y_15_include:

    # "Thirty days hath September,
    #  April, June, and November,
    #  All the rest have thirty-one,
    #  Except February because it's weird, like 28 usually but then 29 on leap years,
    #  and leap years are every 4 years but NOT every 100 years except they ARE every 400 years..."
    #
    # TODO - The code must be updated for the 100 and 400 year rules by 2100 AD

    push r10
    push r11

    mov r11, 1970 # year
y_keep_setting_year:
    mov r9, 365
    mov r15, r11
    xor r10, r10 # is_leap_year
    and r15, 3
    test r15, r15
    jnz not_leap_year
    inc r9
    mov r10, 1
not_leap_year:
    cmp rax, r9
    jl y_year_set
    inc r11
    sub rax, r9
    jmp y_keep_setting_year
y_year_set:
    sub r11, 1900
    shl r11, 16

    mov rsi, 1 # month
y_keep_setting_month:
    mov r9, 31 # default month length
    cmp rsi, 2 # February
    jne y_not_february
    mov r9, 28
    test r10, r10
    jz y_month_length_set
    inc r9
    jmp y_month_length_set
y_not_february:
    cmp rsi, 9 # September
    je y_thirty_day_month
    cmp rsi, 4 # April
    je y_thirty_day_month
    cmp rsi, 6 # June
    je y_thirty_day_month
    cmp rsi, 11 # November
    jne y_month_length_set
y_thirty_day_month:
    dec r9
y_month_length_set:
    cmp rax, r9
    jl y_month_set
    inc rsi
    sub rax, r9
    jmp y_keep_setting_month
y_month_set:
    shl rsi, 8
    add r11, rsi
    inc rax
    add r11, rax

    mov rsi, r11
    pop r11
    pop r10
    push rsi
    
    # 14. 1 vector containing the greatest point which contains a non-space cell, relative to the least point (env)

y_15_exclude:
    test rdi, rdi
    jle y_14_include
    cmp rdi, 14
    jne y_14_exclude
y_14_include:

    # TODO
    push 0
    push 0

    # 13. 1 vector containing the least point which contains a non-space cell, relative to the origin (env)
    #         These two vectors are useful to give to the o instruction to output the entire program source as a text file.
    
y_14_exclude:
    test rdi, rdi
    jle y_13_include
    cmp rdi, 13
    jne y_13_exclude
y_13_include:

    # TODO
    push 0
    push 0

    # 12. 1 vector containing the Funge-Space storage offset of the current IP (ip)

y_13_exclude:
    test rdi, rdi
    jle y_12_include
    cmp rdi, 12
    jne y_12_exclude
y_12_include:

    call get_line_char

    mov rax, r8
    shr rax, 32
    mov edx, r8d
    push rdx # char
    push rax # line

    # 11. 1 vector containing the Funge-Space delta of the current IP (ip)

y_12_exclude:
    test rdi, rdi
    jle y_11_include
    cmp rdi, 11
    jne y_11_exclude
y_11_include:

    test r12, 4
    jnz y_11_not_cardinal
    cmp r12, {DIR_RIGHT}
    jne y_ip_not_right
    push 1
    push 0
    jmp y_11_set
y_ip_not_right:
    cmp r12, {DIR_DOWN}
    jne y_ip_left_or_up
    push 0
    push 1
    jmp y_11_set
y_ip_left_or_up:
    cmp r12, {DIR_LEFT}
    jne y_ip_up
    push -1
    push 0
    jmp y_11_set
y_ip_up:
    push 0
    push -1
    jmp y_11_set
y_11_not_cardinal:
    mov rax, r12
    shr rax, 3
    movzx rdx, ax
    push  rdx
    shr rax, 16
    movzx rax, ax
    push rax
y_11_set:

    # 10. 1 vector containing the Funge-Space position of the current IP (ip)

y_11_exclude:
    test rdi, rdi
    jle y_10_include
    cmp rdi, 10
    jne y_10_exclude
y_10_include:

    call get_line_char
    
    push rdx # char
    push rax # line

    # 9. 1 cell containing a unique team number for the current IP (ip)
    #         Only significant for NetFunge, BeGlad, and the like.

y_10_exclude:
    test rdi, rdi
    jle y_9_include
    cmp rdi, 9
    jne y_9_exclude
y_9_include:

    push 0

    # 8. 1 cell containing a unique ID for the current IP (ip)
    #         Only significant for Concurrent Funge. This ID differentiates this IP from all others currently in the IP list.

y_9_exclude:
    test rdi, rdi
    jle y_8_include
    cmp rdi, 8
    jne y_8_exclude
y_8_include:

    push 0

    # 7. 1 cell containing the number of scalars per vector (global env)
    #         aka number of dimensions. 2 for Befunge, 1 for Unefunge, 3 for Trefunge.

y_8_exclude:
    test rdi, rdi
    jle y_7_include
    cmp rdi, 7
    jne y_7_exclude
y_7_include:

    push 2

    # 6. 1 cell containing a path seperator character (global env)
    #         This is what path seperators for i and o filenames should look like.

y_7_exclude:
    test rdi, rdi
    jle y_6_include
    cmp rdi, 6
    jne y_6_exclude
y_6_include:

    push '/' # since on linux

    # 5. 1 cell containing an ID code for the Operating Paradigm (global env)
    #         0 = Unavailable
    #         1 = Equivalent to C-language system() call behaviour
    #         2 = Equivalent to interpretation by a specific shell or program
    #             This shell or program is specified by the interpreter but should ideally be customizable by the interpreter-user, if applicable. Befunge programs that run under this paradigm should document what program they expect to interpret the string passed to =.
    #         3 = Equivalent to interpretation by the same shell as started this Funge interpreter, if applicable
    #             If the interpreter supports this paradigm, then in this manner, the user executing a Befunge source can easily choose which shell to use for = instructions.
    #         This value is included so the program can have a reasonable idea of what = will do. The values shown here are only the most basic set available at the time of publication. See the Registry for any late-breaking headway into further Operating Paradigms.

y_6_exclude:
    test rdi, rdi
    jle y_5_include
    cmp rdi, 5
    jne y_5_exclude
y_5_include:

    push 0

    # 4. 1 cell containing the implementation's version number (env)
    #         If the version number contains points, they're stripped. v2.01 == 201, v1.03.05 = 10305, v1.5g = 1507. Don't use non-numbers in the version number to indicate 'personalizations' - change the handprint instead.

y_5_exclude:
    test rdi, rdi
    jle y_4_include
    cmp rdi, 4
    jne y_4_exclude
y_4_include:

    # TODO
    push 0

    # 3. 1 cell containing the implementation's handprint (env).

y_4_exclude:
    test rdi, rdi
    jle y_3_include
    cmp rdi, 3
    jne y_3_exclude
y_3_include:

    # "BFDLR"
    mov rax, 0x4246444C52
    push rax

    # 2. 1 cell containing the number of bytes per cell (global env).
    #         aka cell size. Typically 4, could also be 2, 8, really really large, infinity, etc.

y_3_exclude:
    test rdi, rdi
    jle y_2_include
    cmp rdi, 2
    jne y_2_exclude
y_2_include:

    push 8

    # 1. 1 cell containing flags (env).
    #         Least Significant Bit 0 (0x01): high if t is implemented. (is this Concurrent Funge-98?)
    #         Bit 1 (0x02): high if i is implemented.
    #         Bit 2 (0x04): high if o is implemented.
    #         Bit 3 (0x08): high if = is implemented.
    #         Most Significant Bit 4 (0x10): high if unbuffered standard I/O (like getch()) is in effect, low if the usual buffered variety (like scanf("%c")) is being used.
    #         Further more significant bits: undefined, should all be low in Funge-98

y_2_exclude:
    test rdi, rdi
    jle y_1_include
    cmp rdi, 1
    jne y_1_exclude
y_1_include:

    push {0b10000}

y_1_exclude:

    """


    @define_instruction("{")
    @b98
    def push_stack(self):
        return f"""
    pop r9
    test r9, r9
    jge push_stack_non_negative_input
push_stack_negative_input:
    inc r9
    push 0
    test r9, r9
    jnz push_stack_negative_input
push_stack_non_negative_input:
    shl r9, 3
    add r9, rsp

    mov r13, rsp
    mov r15, r8
    mov r10, rbp

    lea rsp, -{STACK_ZERO_SIZE + 24}[r9]
    lea rbp, -24[r9]

    call get_line_char
    mov rdi, rax
    mov rsi, rdx
    call update_line_char
    mov r8, rdi
    shl r8, 32
    mov esi, esi
    or r8, rsi

keep_taking_soss:
    cmp r9, r13
    je toss_took_soss
    sub r9, 8
    push qword ptr [r9]
    mov qword ptr [r9], 0
    jmp keep_taking_soss
toss_took_soss:

    mov qword ptr [rbp], r10
    mov r10d, r15d
    mov qword ptr 8[rbp], r10
    mov r10, r15
    shr r10, 32
    mov qword ptr 16[rbp], r10

    """


    @define_instruction("}")
    @b98
    def pop_stack(self):
        return f"""
    pop r9

    mov rsi, rsp
    mov rdi, rsp
    shl r9, 3
    add rsi, r9

    cmp qword ptr [rbp], 0
    je cant_pop_last_stack
    mov r8d, dword ptr 8[rbp]
    mov r15, qword ptr 16[rbp] 
    shl r15, 32
    or r8, r15

    lea rsp, 24[rbp]
    mov rbp, qword ptr [rbp]
soss_keep_removing:
    test r9, r9
    jge soss_done_removing
    add rsp, 8
    add r9, 8
    jmp soss_keep_removing
soss_done_removing:
    cmp rsi, rdi
    jle soss_done_adding
    sub rsi, 8
    push qword ptr [rsi]
    jmp soss_done_removing
cant_pop_last_stack:
    call reflect
soss_done_adding:
    """


    @define_instruction("u")
    @b98
    def stack_under_stack(self):
        return f"""
    pop r9

    mov rsi, rsp
    shl r9, 3
    sub rsi, r9

    cmp qword ptr [rbp], 0
    je u_cant_pop_last_stack
    mov r15, qword ptr [rbp]
    test r9, r9
    jl u_neg
u_pos: # soss to toss
    cmp rsp, rsi
    je u_done
    push qword ptr 8[rbp]
    mov qword ptr [rbp], 0
    add rbp, 8
    jmp u_pos
u_neg: # toss to soss
    cmp rsp, rsi
    je u_done
    pop r9
    mov qword ptr [rbp], r9
    sub rbp, 8
    jmp u_neg
u_cant_pop_last_stack:
    call reflect
u_done:
    mov qword ptr [rbp], r15
    """


    @fingerprint("BOOL")
    @define_instruction("A")
    def bool_and(self):
        return f"""
    pop rdi
    pop rsi
    and rdi, rsi
    not rdi
    not rdi
    push rdi
    """


    @fingerprint("BOOL")
    @define_instruction("N")
    def bool_not(self):
        return f"""
    pop rdi
    not rdi
    push rdi
    """


    @fingerprint("BOOL")
    @define_instruction("O")
    def bool_or(self):
        return f"""
    pop rdi
    pop rsi
    or rdi, rsi
    not rdi
    not rdi
    push rdi
    """


    @fingerprint("BOOL")
    @define_instruction("X")
    def bool_xor(self):
        return f"""
    pop rdi
    pop rsi
    xor rdi, rsi
    not rdi
    not rdi
    push rdi
    """


    @fingerprint("RAND")
    @define_instruction("I")
    def rand_get_rand(self):
        return f"""
    pop rdi
    mov rax, qword ptr [rand_seed]
    mov rdx, 1103515245
    mul rdx
    add rax, 12345
    mov qword ptr [rand_seed], rax
    cqo
    idiv rdi
    push rdx
    """

    
    @fingerprint("RAND")
    @define_instruction("M")
    def rand_get_max(self):
        return f"""
    xor rdi, rdi
    dec rdi
    shr rdi, 1
    push rdi
    """


    @fingerprint("RAND")
    @define_instruction("R")
    def rand_get_fpsp_rand(self):
        return f"""
    # NOT SUPPORTED ; REFLECT
    push r14
    call reflect
    pop r14
    """


    @fingerprint("RAND")
    @define_instruction("S")
    def rand_seed_rand(self):
        return f"""
    pop rax
    mov qword ptr [rand_seed], rax
    """


    @fingerprint("RAND")
    @define_instruction("T")
    def rand_seed_rand_time(self):
        return f"""
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov qword ptr [rand_seed], rax
    """


    @fingerprint("BASE")
    @define_instruction("B")
    def base_write_binary_int(self):
        return f"""
    pop rax

    push r14
    push r12
    mov r13, rsp
    mov rsi, 1
    dec rsp
    mov byte ptr [rsp], ' '

    test rax, rax
    jnz B_not_zero
    dec rsp
    inc rsi
    mov byte ptr [rsp], '0'
    jmp B_number_built
B_not_zero:
    mov rdx, rax
    shr rax, 1
    and rdx, 1

    dec rsp
    inc rsi
    add rdx, '0'
    mov byte ptr [rsp], dl

    test rax, rax
    jne B_not_zero

B_number_built:
    mov rax, 1
    mov rdi, 1
    mov rdx, rsi
    lea rsi, [rsp]
    push r11
    syscall
    pop r11

    mov rsp, r13
    pop r12
    pop r14
    """


    @fingerprint("BASE")
    @define_instruction("H")
    def base_write_hex_int(self):
        return f"""
    pop rax

    push r14
    push r12
    mov r13, rsp
    mov rsi, 1
    dec rsp
    mov byte ptr [rsp], ' '

    test rax, rax
    jnz H_not_zero
    dec rsp
    inc rsi
    mov byte ptr [rsp], '0'
    jmp H_number_built
H_not_zero:
    mov rdx, rax
    and rdx, {0b1111}
    shr rax, 4

    dec rsp
    inc rsi
    cmp rdx, 9
    jg H_is_letter
    add rdx, '0'
    jmp H_char_is_ready
H_is_letter:
    add rdx, {ord('A') - 10}
H_char_is_ready:
    mov byte ptr [rsp], dl

    test rax, rax
    jne H_not_zero
H_number_built:
    mov rax, 1
    mov rdi, 1
    mov rdx, rsi
    lea rsi, [rsp]
    push r11
    syscall
    pop r11

    mov rsp, r13
    pop r12
    pop r14
    """


    @fingerprint("BASE")
    @define_instruction("I")
    def base_read_int_in_base(self):
        return f"""
    pop rcx # base
    movzx rcx, cl

    push r14
    push r12
    push r11
    push 0
    
I_skip_whitespace:
    mov rax, 0
    mov rdi, 0
    lea rsi, [rsp]
    mov rdx, 1
    push rcx
    syscall
    pop rcx

    cmp byte ptr [rsp], ' '
    je I_skip_whitespace
    cmp byte ptr [rsp], '\\n'
    je I_skip_whitespace
    cmp byte ptr [rsp], '\\t'
    je I_skip_whitespace

    xor r13, r13
    xor r15, r15
    cmp byte ptr [rsp], '-'
    jne I_read_int_loop

    inc r15 # is negative
    mov rax, 0
    mov rdi, 0
    lea rsi, [rsp]
    mov rdx, 1
    push rcx
    syscall
    pop rcx

I_read_int_loop:
    cmp byte ptr [rsp], '9'
    ja I_not_digit
    cmp byte ptr [rsp], '0'
    jb I_not_digit
    sub byte ptr [rsp], '0'
    jmp I_digit_read
I_not_digit:
    cmp byte ptr [rsp], 'Z'
    ja I_not_uppercase
    cmp byte ptr [rsp], 'A'
    jb I_not_uppercase
    sub byte ptr [rsp], 'A'
    add byte ptr [rsp], 10
    jmp I_digit_read
I_not_uppercase:
    cmp byte ptr [rsp], 'z'
    ja I_int_reading_complete
    cmp byte ptr [rsp], 'a'
    jb I_int_reading_complete
    sub byte ptr [rsp], 'a'
    add byte ptr [rsp], 10
I_digit_read:
    cmp byte ptr [rsp], cl
    jae I_int_reading_complete

    mov rax, r13
    imul rcx
    mov r13, rax
    movzx rax, byte ptr [rsp]
    add r13, rax

    mov rax, 0
    mov rdi, 0
    lea rsi, [rsp]
    mov rdx, 1
    push rcx
    syscall
    pop rcx

    jmp I_read_int_loop
I_int_reading_complete:
    test r15, r15
    jz I_int_not_negative
    neg r13
I_int_not_negative:
    pop r11
    pop r11
    pop r12
    pop r14
    push r13
    """


    @fingerprint("BASE")
    @define_instruction("N")
    def base_write_int_in_base(self):
        return f"""
    pop rax
    pop rcx

    push r14
    push r12
    mov r13, rsp
    mov rsi, 1
    dec rsp
    mov byte ptr [rsp], ' '

    test rax, rax
    jnz N_not_zero
    dec rsp
    inc rsi
    mov byte ptr [rsp], '0'
    jmp N_number_built
N_not_zero:
    cqo
    idiv rcx

    test rax, rax
    jz N_last_digit
    test rdx, rdx
    jge N_digit_positive
    neg rdx
N_digit_positive:
    dec rsp
    inc rsi
    add rdx, '0'
    cmp rdx, '9'
    jbe N_is_digit
    add rdx, {ord('A') - ord('0') - 10}
N_is_digit:
    mov byte ptr [rsp], dl
    jmp not_zero

N_last_digit:
    test rdx, rdx
    jge N_last_digit_positive
    neg rdx
    dec rsp
    inc rsi
    add rdx, '0'
    mov byte ptr [rsp], dl
    dec rsp
    inc rsi
    mov byte ptr [rsp], '-'
    jmp N_number_built

N_last_digit_positive:
    dec rsp
    inc rsi
    add rdx, '0'
    mov byte ptr [rsp], dl

N_number_built:
    mov rax, 1
    mov rdi, 1
    mov rdx, rsi
    lea rsi, [rsp]
    push r11
    syscall
    pop r11

    mov rsp, r13
    pop r12
    pop r14
    """


    @fingerprint("BASE")
    @define_instruction("O")
    def base_write_octal_int(self):
        return f"""
    pop rax

    push r14
    push r12
    mov r13, rsp
    mov rsi, 1
    dec rsp
    mov byte ptr [rsp], ' '

    test rax, rax
    jnz O_not_zero
    dec rsp
    inc rsi
    mov byte ptr [rsp], '0'
    jmp O_number_built
O_not_zero:
    mov rdx, rax
    and rdx, {0b111}
    shr rax, 3

    dec rsp
    inc rsi
    add rdx, '0'
    mov byte ptr [rsp], dl

    test rax, rax
    jne O_not_zero
O_number_built:
    mov rax, 1
    mov rdi, 1
    mov rdx, rsi
    lea rsi, [rsp]
    push r11
    syscall
    pop r11

    mov rsp, r13
    pop r12
    pop r14
    """


    @fingerprint("FORK")
    @define_instruction("T")
    def fork_process(self):
        return f"""

    mov rax, 57 # fork

    push r14
    push r12
    push r11
    syscall
    pop r11
    pop r12
    pop r14

    test rax, rax
    jl fork_fail
    jz fork_child
    push rax
    push 0 # parent
    jmp fork_complete
fork_child:
    mov rax, 110 # getppid
    push r14
    push r12
    push r11
    syscall
    pop r11
    pop r12
    pop r14
    push rax
    push 1 # child
    call reflect
    jmp fork_complete
fork_fail:
    push 0
    push -1
fork_complete:
    """
