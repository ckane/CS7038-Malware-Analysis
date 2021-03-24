# Retrieves and displays the summary counts for instructions used within
# a function.
#
# @category CS6038.Demo
# 
# Use the Python json library
import json

# Import some of the Ghidra classes we will be using
from ghidra.util.task import ConsoleTaskMonitor

# Initialize an empty dict for the "all functions" report
fn_report = {}

# the Program.getFunctionManager() provides an interface to navigate the functions
# that Ghidra has found within the program. The getFunctions() method will provide
# an iterator that allows you to walk through the list forward (True) or
# backward (False).
for fn in getCurrentProgram().getFunctionManager().getFunctions(True):

    # Get the earliest instruction defined within the function, to start our exploration
    instr = getInstructionAt(fn.getBody().getMinAddress())

    # If it is defined, then we assume this is a navigable function and create an entry
    # for it in fn_report
    if instr:
        fn_report[fn.getName()] = {}

    # This code is largely the same as the GetFunctionInstructions.py code, with the change
    # that it uses the functions provided from the aforementioned iterator, rather than the
    # function from the cursor position
    while instr and instr.getMinAddress() <= fn.getBody().getMaxAddress():
        if fn.getBody().contains(instr.getMinAddress()):
            opcode = instr.getMnemonicString()

            if opcode in fn_report[fn.getName()]:
                fn_report[fn.getName()][opcode] += 1
            else:
                fn_report[fn.getName()][opcode] = 1

        instr = instr.getNext()

# Display the report to the console
print(json.dumps(fn_report, sort_keys=True, indent=2))

# The below is useful if you want to print raw JSON for machine-machine handling
#print(json.dumps(fn_report))
