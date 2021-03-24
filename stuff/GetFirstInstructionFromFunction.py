# Retrieves and displays the summary counts for instructions used within
# a function.
#
# @category CS6038.Demo
# 

# Import some of the Ghidra classes we will be using
from ghidra.util.task import ConsoleTaskMonitor

# Get the function where the cursor is presently located
fn = getFunctionContaining(currentAddress)

# Identify where the first instruction is within the function
instr = getFirstInstruction(fn)

# Print the mnemonic (the text name) of the opcode to the console
print(instr.getMnemonicString())
