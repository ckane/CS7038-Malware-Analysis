# Cleans up some ostream << operations, displaying the cleaned up source code on the console
#
# @category CS6038.Demo
#

# Import some of the Ghidra classes we will be using
from ghidra.app.decompiler import DecompInterface, PrettyPrinter
from ghidra.util.task import ConsoleTaskMonitor

# Import addition Python classes we want to use
import re

# This function is implemented as a callback to re.sub(...), and it will be called for each
# match, and will return the string content that the matched text is to be replaced with
def sub_stmt(matches):
    # The "capture groups" defined in the regex were made to extract each argument passed to
    # the operator<< function call.
    larg = matches.group(1)
    rarg = matches.group(2)

    # Reorganize these arguments so that they reflect the infix-syntax ostream << operation
    return larg + " << " + rarg + ";"

# Instantiate a new Decompiler session to work with - this will be independent of the
# session being used to render the Decompiler view
decomp = DecompInterface()

# Open the current program (again) with the Decompiler. This is necessary, because you
# might want to open a different program to decompile with this script, and Ghidra allows that. So
# you need to be explicit if you want to decompile this program
decomp.openProgram(currentProgram)

# Find the current address shown in the UI, and ask Ghidra to provide the Function that contains
# that address. This function is a member of FlatProgramAPI, and demonstrates how to access these
# class and parent-class methods from within your script.
fn = getFunctionContaining(currentAddress)

# Tell the decompiler to decompile the function we identified. You'll want to provide a timeout
# if anything goes wrong, and this function accepts the monitor object which provides the TaskMonitor
# argument
decomp_results = decomp.decompileFunction(fn, 30, monitor)

# The below sequence is intentionally building a string for the regex pattern piece by piece, so that
# I can document it for you.
ostream_regex =  r'operator\<\<'     # Start match with 'operator<<'
ostream_regex += r'(?:\<[^;]*\>)?'   # Then, allow there to be one or no template specifiers
ostream_regex += r'\s*'              # Match zero or more whitespace, to be flexible
ostream_regex += r'\('               # Then, look for an open parenthesis
ostream_regex += r'\s*'              # Match zero or more whitespace, to be flexible


# Captures the first argument passed to the operator<< function call
ostream_regex += r'('                # Start definition for first capture group
ostream_regex += r'[^;\(\)\<\>,]*'   # Match on an argument, which could be anything not matching
                                     # the semicolon, comma, or template/parenthesis characters
ostream_regex += r'(?:\<[^;]+\>|\([^;]+\))*' # Allow there to be zero or more characters inside
                                             # of the argument that represent <> or () grouped
                                             # statements
ostream_regex += r'[^;\(\)\<\>,]*'   # Match on an argument, which could be anything not matching
                                     # the semicolon, comma, or template/parenthesis characters
ostream_regex += r')'                # Define the end of the first match/extract group

ostream_regex += r'\s*,\s*'          # Next arg is preceded by comma, with any amount of whitespace around it


# Captures the second argument passed to the operator<< function call
ostream_regex += r'([^;]*)'          # Match any character that isn't a semicolon as a potential second argument,
                                     # and capture this as group #2

ostream_regex += r'\s*'              # Match zero or more whitespace, to be flexible
ostream_regex += r'\)'               # Function call must have a closing parenthesis
ostream_regex += r'\s*;'             # Match zero or more whitespace, then semicolor, to end string

# Compile the patter into a regex matcher. Python has you do this, because compiling the regular
# expression can frequently take more time than actually matching with it. Doing this once, and then
# reusing the "compiled" version helps your code run a lot faster.
ostream_pat = re.compile(ostream_regex)

# Determine if the Decompiler completed successfully or failed
if decomp_results.decompileCompleted():
    # Pass the DecompileResults to the PrettyPrinter, to create a new PrettyPrinter interface
    # to pull collected code from. This also requires the Function to be passed to it again.
    pp = PrettyPrinter(fn, decomp_results.getCCodeMarkup())

    # Get the string of the full function source code
    code = pp.print(False).getC()

    # use the (sub)stitute function from re to substitute all matches in the program with
    # simplified text
    n = ostream_pat.sub(sub_stmt, code)

    # Print the adjusted results to the console
    print(n)
else:
    print("There was an error in decompilation!")
