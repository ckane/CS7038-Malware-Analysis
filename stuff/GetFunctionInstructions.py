# Retrieves and displays the summary counts for instructions used within
# a function.
#
# @category CS6038.Demo
# 

# Use the JSON library for output
import json

# Import some of the Ghidra classes we will be using
from ghidra.util.task import ConsoleTaskMonitor

# Get the function where the cursor is presently located
fn = getFunctionContaining(currentAddress)

# Use AddressSetView.getMinAddress() to get the location of the earliest fragment of the function
instr = getInstructionAt(fn.getBody().getMinAddress())

# We want to store the results in a Python dict data structure. Each key will have an instruction
# mnemonic, while each value will be the counts, with absent instructions representing zero counts
instr_map = {}

# Make sure that the instruction we're analyzing is not outside of the function's max memory range
while instr.getMinAddress() <= fn.getBody().getMaxAddress():
    # If the instruction is contained by one of the fragments represented in the AddressSetView, then
    # it is part of the code for the function, and we should count it
    if fn.getBody().contains(instr.getMinAddress()):
        # Get the string mnemonic name from the instruction
        opcode = instr.getMnemonicString()

        # If an entry exists in the dict, then increment its counter, otherwise, create a new entry
        # populated with 1
        if opcode in instr_map:
            instr_map[opcode] += 1
        else:
            instr_map[opcode] = 1

    # Advance the cursor to the next instruction
    instr = instr.getNext()

print(json.dumps(instr_map, sort_keys=True, indent=2))

# The below line will be useful for saving the output to a file handle for machine processing
# print(json.dumps(instr_map))
