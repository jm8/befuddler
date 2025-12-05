# Befuddler

Befunge-93 compiler used in the BuckeyeCTF 2025 challenges `rev / befuddled` and `rev / befucked`

## Usage

```sh
./befuddler.py [--width WIDTH] [--height HEIGHT] [--fit_size] [--b98] source
```

The standard compiler is the Befunge-93 compiler, however some limited Befunge-98 is supported (WIP).

With the `--b98` flag, the funge-space is still a fixed space, however it can be changed with the other flags.

`--fit_size` will fit the size to the maximum character and line in the source file.

## Debugger

There is a debugger that allows you to watch the funge space and the cursor as the program executes.

[Screencast From 2025-11-18 14-08-10.webm](https://github.com/user-attachments/assets/1f13ce28-ba40-45f0-9967-54f2e87ea8a4)

To use it, first compile your program

```sh
./befuddler.py examples/hello_world.bf
```

Then run gdb in one terminal with the gdbscript: 
```sh
gdb -x gdbscript.gdb examples/hello_world
```

And in another terminal run the python script which watches the gdb logs (`gdb.txt`) which are output from the gdbscript.
```sh
./debugger.py
```

Step through the program using `c` in the gdb terminal.

## Testing

[Mycology](https://github.com/Deewiant/Mycology) is a standard Befunge test suite. Run `./test_mycology.sh` to run these tests and verify that the output looks as expected.

The script will clone the Mycology repo for you, compile each Befunge-93 program, run it, display the output, and remove the compiled code afterwards.

## Technical Detail

The compiled Befunge code works by writing each instruction as a 5-byte jump instruction, followed by a 5-byte call to a function which jumps to the next instruction.

By doing this, we create a fixed-size grid, with 10 bytes per Befunge instruction. We also use a dedicated direction register to be able to calculate the next instruction to jump to.

On either side and above and below the grid, there are two layers of extraneous jump instructions. This makes wrapping possible, as moving to these instructions will automatically jump to the appropriate position. The second layer handles the case where a `#` instruction is at a border.

![Code memory layout](./assets/code_memory.png)

The "true" funge-space is still stored somewhere in memory, as must be the case for properly functioning `g`, `p`, and `"` instructions. However, it is only referenced for these instructions, and the rest are compiled. Using the `p` instruction only requires overwriting a single 5-byte jump instruction. To improve efficiency of the implementation of some instructions, each line in the funge-space is padded with bytes corresponding to the extraneous jump instructions in the text segment.

### Fingerprints

Fingerprints in the Befunge-98 mode currently have limited support.

The way they work, unlike other instructions, is that their functions use a lookup table of the current pointers to the relevant functions. Every time a fingerprint is loaded, it replaces elements of that lookup table.

The `)` instruction currently always reflects after popping off the arguments. `(` just replaces whatever it needs in the current lookup table.

Current fingerprints:
 - `BOOL`
 - `RAND` (`R` not supported due to lack of `FPSP`)
 - `BASE`

## Known Limitations

To implement popping `0` from the stack when it is empty, we simply push a large number of zero bytes onto the stack at the start of each program. This may make generated programs vulnerable to stack smashing attacks.
