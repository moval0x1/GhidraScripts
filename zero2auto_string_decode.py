#Decode strings used in custom sample from Zero2Auto course
#@author Charles Lomboni
#@category Zero2Auto
#@keybinding 
#@menupath 
#@toolbar 

import ghidra

# **************************** GET STRING ****************************

def get_string(addr):
	mem = currentProgram.getMemory()
	core_name_str = ""
	while True:
		byte = mem.getByte(addr.add(len(core_name_str)))
		if byte == 0:
			return core_name_str
		core_name_str += chr(byte)

# **************************** DECODE STRING ****************************
def decode_str(encoded_str):
    """
        Decode strings used in custom sample from Zero2Auto course
    """
    base_str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./="
    new_char = 0
    decoded_str = []

    for x in encoded_str:
        str_diff = (base_str.index(x) + 0xD)
        if str_diff < 66:
            decoded_str.append(base_str[str_diff])
        else:
            new_char = (base_str.index(x) - 66) + 0xD
            decoded_str.append(base_str[new_char])
        
    return ''.join(decoded_str)

# **************************** SET COMMENT ****************************
def set_comment(instruction, item):
    str_off = toAddr(instruction.getDefaultOperandRepresentation(1))
    str_encoded = get_string(str_off)

    decoded_str = decode_str(str_encoded)

    # write deobfuscated string in comments
    comment_addr = (getInstructionAfter(getInstructionAfter(item.getFromAddress()))).getAddress()
    listing = currentProgram.getListing()
    codeUnit = listing.getCodeUnitAt(comment_addr)
    codeUnit.setComment(codeUnit.EOL_COMMENT, '[*] ' + decoded_str)

    print (f"[*] Address 0x{comment_addr.toString()}:  {decoded_str}")

# **************************** RENAME FUNCTION ****************************
def rename_function(old_name, new_name):

	old_function_name = getGlobalFunctions(old_name)
	for func_name in old_function_name:
		# Get reference to `register_function`
		function_manager = currentProgram.getFunctionManager()
		
		# Set the comments
		core_func_obj = function_manager.getFunctionAt(func_name.getEntryPoint())
		core_func_obj.setName(new_name, ghidra.program.model.symbol.SourceType.DEFAULT)

		print (f"[*] Renamed from {old_name} to {new_name}")

# **************************** MAIN ****************************
def main():
	"""Main"""

	print ("[*] Deobfuscating strings...")
	decrypt_function_old_name = "FUN_00401300"
	decrypt_function_new_name = "mw_decrypt_str"

	for x in getReferencesTo(toAddr(decrypt_function_old_name)):
		rename_function(decrypt_function_old_name, decrypt_function_new_name)

		callee = x.getFromAddress()
		inst = getInstructionAt(callee)

		before = getInstructionBefore(inst)

		if 'MOV ECX' in before.toString():
			try:
				set_comment(before, x)
			except ValueError:
				pass
		else:
			before_one_more = getInstructionBefore(before)
            
			if 'MOV ECX' in before_one_more.toString():
				try:
					set_comment(before_one_more, x)
				except ValueError:
					pass

	print ("[*] Done.")


if __name__ == '__main__':
	main()