# Retrieves and displays the summary counts for P-Code ops used within
# a function.
#
# @category CS6038.Demo
# 
# Use the Python json library
import json

# Add the Python argument parser
from argparse import ArgumentParser

# Import some of the Ghidra classes we will be using
from ghidra.util.task import ConsoleTaskMonitor

# Initialize an empty dict for the "all functions" report
fn_report = {}

# Set up parser for the script arguments
arg_parser = ArgumentParser(description="P-Code statistical analysis", prog='script', prefix_chars='+')
arg_parser.add_argument('+o', '++output', required=True, help='Output file for JSON')
args = arg_parser.parse_args(args=getScriptArgs())

# the Program.getFunctionManager() provides an interface to navigate the functions
# that Ghidra has found within the program. The getFunctions() method will provide
# an iterator that allows you to walk through the list forward (True) or
# backward (False).
for fn in getCurrentProgram().getFunctionManager().getFunctions(True):

    # Get the earliest instruction defined within the function, to start our exploration
    instr = getInstructionAt(fn.getBody().getMinAddress())

    # Walk through each instruction that's determined to be part of this function
    while instr and instr.getMinAddress() <= fn.getBody().getMaxAddress():
        if fn.getBody().contains(instr.getMinAddress()):
            # Iterate across the list of P-Code operations that are expanded from
            # the parsed machine instruction
            for pcode_op in instr.getPcode():

                # Get the string name of the PCode operation
                pcode_name = pcode_op.getMnemonic()

                # Create a new report for this function the first time we get a valid instruction
                if fn.getName() not in fn_report:
                    fn_report[fn.getName()] = {}

                if pcode_name in fn_report[fn.getName()]:
                    fn_report[fn.getName()][pcode_name] += 1
                else:
                    fn_report[fn.getName()][pcode_name] = 1

        # Advance to the next instruction
        instr = instr.getNext()

# Now, open the file provided by the user, and write the JSON into it
with open(args.output, 'w') as outfile:
    outfile.write(json.dumps(fn_report))
