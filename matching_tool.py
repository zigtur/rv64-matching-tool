import sys
from elftools.elf.elffile import ELFFile
import re
import json

def extract_text_section_instructions(elf_path):
    """
    Extract and print executable instructions from the .text section of a RISC-V ELF binary.
    
    Args:
    - elf_path (str): Path to the ELF binary file.
    
    Returns:
    - List of hexadecimal instructions from the .text section.
    """
    try:
        with open(elf_path, 'rb') as f:
            elffile = ELFFile(f)

            # Check if the ELF is for RISC-V architecture (EM_RISCV = 243)
            if elffile['e_machine'] != 'EM_RISCV':
                print(f"Error: ELF is not for RISC-V (detected: {elffile['e_machine']})")
                exit(1)

            # Get the .text section
            text_section = elffile.get_section_by_name('.text')
            if text_section is None:
                print(f"Error: Could not find the .text section in {elf_path}")
                exit(1)

            # Extract the raw bytes from the .text section
            text_data = text_section.data()

            # Divide the text section data into 32-bit (4-byte) RISC-V instructions
            instructions = []
            for i in range(0, len(text_data), 4):
                # Extract a 32-bit instruction (since RISC-V instructions are 32-bit)
                instruction_bytes = text_data[i:i + 4]
                if len(instruction_bytes) < 4:
                    break  # If the remaining bytes are less than 4, stop
                instruction = int.from_bytes(instruction_bytes, byteorder='little')
                instructions.append(instruction)

            return instructions

    except FileNotFoundError:
        print(f"Error: File '{elf_path}' not found.")
        exit(1)
    except Exception as e:
        print(f"Error: Unable to read the ELF file. Reason: {e}")
        exit(1)
    

def parse_funct3(instr):
    # Corresponds to parsing in VM
    return (instr >> 12) & 0x7

def parse_funct7(instr):
    # Corresponds to parsing in VM
    return (instr >> 25)

def parse_opcode(instr):
    # Corresponds to parsing in VM
    return instr & 0x7F

def instruction_name(instruction, supported):
    opcode = parse_opcode(instruction)
    funct3 = parse_funct3(instruction)
    funct7 = parse_funct7(instruction)
    
    opcode_hex = f"{opcode:02X}"
    funct3_hex = f"{funct3:02X}"
    funct7_hex = f"{funct7:02X}"
    
    for opcode_entry in supported['opcodes']:
        if opcode_hex in opcode_entry:
            opcode_data = opcode_entry[opcode_hex]
            
            # Check if it's a direct instruction like LUI, JAL, etc.
            if isinstance(opcode_data, str):
                return opcode_data
            
            # Check for funct3-based instructions
            if 'funct3' in opcode_data:
                for funct3_entry in opcode_data['funct3']:
                    if funct3_hex in funct3_entry:
                        return funct3_entry[funct3_hex]

            # Check for funct7-based instructions
            if 'funct7' in opcode_data:
                for funct7_entry in opcode_data['funct7']:
                    if funct7_hex in funct7_entry:
                        funct7_data = funct7_entry[funct7_hex]
                        if 'funct3' in funct7_data:
                            for funct3_entry in funct7_data['funct3']:
                                if funct3_hex in funct3_entry:
                                    return funct3_entry[funct3_hex]
                    elif 'default' in funct7_entry:
                        funct7_data = funct7_entry['default']
                        if 'funct3' in funct7_data:
                            for funct3_entry in funct7_data['funct3']:
                                if funct3_hex in funct3_entry:
                                    return funct3_entry[funct3_hex]

    return "UNKNOWN"

def parse_instructions(instructions, json_path):
    """
    Parse each RISC-V instruction from the input instructions.
    
    Args:
    - instructions: Array of instructions.

    Returns:
    - instructions_count: a dictionary that maps each instruction with its number of occurence.
    - unknown_instructions: a dictionary mapping unknown instruction with its number of occurence.
    """    
    last_bytes = {}
    unknown_instructions = {}
    supported = dict_from_json(json_path)

    u32max = (2**32)-1
    for instruction in instructions:
        if instruction < u32max:  # Ensure it is a full 32-bit instruction
            ins_name = instruction_name(instruction, supported)
            # Increment the count of this opcode in the dictionary
            if ins_name == "UNKNOWN":
                unknown_instructions[instruction] = unknown_instructions.get(instruction, 0) + 1
            last_bytes[ins_name] = last_bytes.get(ins_name, 0) + 1
        else:
            print(f"Error: Unexpected instruction: {instruction}.")
            exit(1)
            

    return last_bytes, unknown_instructions

def dict_from_json(json_path):
    try:
        with open(json_path, 'r') as f:
            supported = json.load(f)
            return supported

    except FileNotFoundError:
        print(f"Error: File '{elf_path}' not found.")
        exit(1)
    except Exception as e:
        print(f"Error: Unable to read the JSON file. Reason: {e}")
        exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 parse_riscv_elf.py <path_to_elf_file> <path_to_json_file>")
        sys.exit(1)
    
    elf_path = sys.argv[1]
    json_path = sys.argv[2]
    instructions = extract_text_section_instructions(elf_path)
    
    instruction_counts, unknown = parse_instructions(instructions, json_path)

    if instruction_counts.get("UNKNOWN", 0) != 0:
        nb_unknown = instruction_counts["UNKNOWN"]
        print(f"There were {nb_unknown} unknown instructions.\n")
        for instru, count in sorted(unknown.items()):
            print(f"Unknown instruction: {instru:08X}: {count} times")
        exit(1)
    else:
        print("All instructions known.")
