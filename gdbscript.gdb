set logging enabled on
set pagination off
printf "PROGRAM_START((%#lx))\n", &code_space_start
printf "WIDTH((%#lx))\n", (long)width
printf "HEIGHT((%#lx))\n", (long)height
b nexti_exit
commands
printf "STACK((%#lx))\n", *(long*)$rsp
python
import gdb
addr = int(gdb.parse_and_eval("(char*)&funge_space"))
width = int(gdb.parse_and_eval("(long)width"))
height = int(gdb.parse_and_eval("(long)height"))
mem = gdb.selected_inferior().read_memory(addr, (width + 4)*height)
print(f"FUNGE_SPACE(({mem.hex()}))")
end
end
r
