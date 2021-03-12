# Retrieves and displays the decompiler output for the current function in the console
#
# @category CS6038.Demo
#

# Import some of the Ghidra classes we will be using
from ghidra.app.decompiler import DecompInterface, PrettyPrinter
from ghidra.util.task import ConsoleTaskMonitor

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

# Determine if the Decompiler completed successfully or failed
if decomp_results.decompileCompleted():
    # Pass the DecompileResults to the PrettyPrinter, to create a new PrettyPrinter interface
    # to pull collected code from. This also requires the Function to be passed to it again.
    pp = PrettyPrinter(fn, decomp_results.getCCodeMarkup())

    # Get a string containing the decompiled function code. Passing "False" here tells it not
    # to "replace invalid characters", which is the reason why you saw the symbol replacements
    # in the prior example. In this case, the code output by this decompiler may no longer
    # conform to simple C-language syntax, as it now contains some C++-specific extensions.
    code = pp.print(False).getC()

    # Print it out to the console
    print(code)
else:
    print("There was an error in decompilation!")
