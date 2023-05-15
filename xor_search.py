# Search for all XOR with some hardcode Hex value in the program
# @author Charles Lomboni (charlesl@securityjoes.com)
# @category SecurityJoes
# @keybinding
# @menupath
# @toolbar

import ghidra

# For type checking
try:
    from ghidra.ghidra_builtins import *
except:
    pass


def run():
    # Get all instruction from the binary
    instructions = currentProgram.getListing().getInstructions(True)

    for ins in instructions:
        mnemonic = ins.getMnemonicString()
        if mnemonic == "XOR":
            operand1 = ins.getOpObjects(0)
            operand2 = ins.getOpObjects(1)
            if '0x' in str(operand1) or '0x' in str(operand2):
                print(f"[+] Address: {ins.address} - {ins}")


run()
