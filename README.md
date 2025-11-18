# Befuddler

Befunge-93 compiler used in the BuckeyeCTF 2025 challenges `rev / befuddled` and `rev / befucked`

## Testing

[Mycology](https://github.com/Deewiant/Mycology) is a standard Befunge test suite. Run `./test_mycology.sh` to run these tests and verify that the output looks as expected.

The script will clone the Mycology repo for you, compile each Befunge-93 program, run it, display the output, and remove the compiled code afterwards.

## Technical Detail

The compiled Befunge code works by writing each instruction as a 5-byte jump instruction, followed by a 5-byte call to a function which jumps to the next instruction.

By doing this, we create a fixed-size grid, with 10 bytes per Befunge instruction. We also use a dedicated direction register to be able to calculate the next instruction to jump to.

On either side and above and below the grid, there are two layers of extraneous jump instructions. This makes wrapping possible, as moving to these instructions will automatically jump to the appropriate position. The second layer handles the case where a `#` instruction is at a border.

![Code memory layout](./assets/code_memory.png)

The "true" funge-space is still stored somewhere in memory, as must be the case for properly functioning `g`, `p`, and `"` instructions. However, it is only referenced for these instructions, and the rest are compiled. Using the `p` instruction only requires overwriting a single 5-byte jump instruction. To improve efficiency of the implementation of some instructions, each line in the funge-space is padded with bytes corresponding to the extraneous jump instructions in the text segment.

## Known Limitations

To implement popping `0` from the stack when it is empty, we simply push a large number of zero bytes onto the stack at the start of each program. This may make generated programs vulnerable to stack smashing attacks.
