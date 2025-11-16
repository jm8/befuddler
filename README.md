# befunge compiler

Befunge compiler used in the BuckeyeCTF 2025 challenges `rev / befuddled` and `rev / befucked`

## Testing

[Mycology](https://github.com/Deewiant/Mycology) is a standard Befunge test suite. Run `./test_mycology.sh` to run these tests and verify that the output looks as expected.

The script will clone the Mycology repo for you, compile each Befunge-93 program, run it, display the output, and remove the compiled code afterwards.
