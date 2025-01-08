import sys
import os
import platform

if platform.system() == "Windows":
    path = os.path.join(os.environ["USERPROFILE"], "Documents")
else:
    path = os.path.join(os.path.expanduser("~"), "Documents")

label = {}

def parse(line, code_addr: int):
    REG_LIST = dict([("R0", 0x0), ("R1", 0x1), ("R2", 0x2), ("R3", 0x3), ("R4", 0x4),
                    ("R5", 0x5), ("R6", 0x6), ("R7", 0x7), ("R8", 0x8), ("R9", 0x9),
                    ("R10", 0xa), ("R11", 0xb), ("R12", 0xc), ("R13", 0xd), ("R14", 0xe),
                    ("R15", 0xf), ("R16", 0x10), ("R17", 0x11), ("R18", 0x12), ("R19", 0x13),
                    ("R20", 0x14), ("R21", 0x15), ("R22", 0x16), ("R23", 0x17), ("R24", 0x18),
                    ("R25", 0x19), ("R26", 0x1a), ("R27", 0x1b), ("R28", 0x1c), ("R29", 0x1d),
                    ("R30", 0x1e), ("R31", 0x1f), ("R32", 0x20), ("R33", 0x21), ("R34", 0x22),
                    ("R35", 0x23), ("R36", 0x24), ("R37", 0x25), ("R38", 0x26), ("R39", 0x27),
                    ("R40", 0x28), ("R41", 0x29), ("R42", 0x2a), ("R43", 0x2b), ("R44", 0x2c),
                    ("R45", 0x2d), ("R46", 0x2e), ("R47", 0x2f), ("R48", 0x30), ("R49", 0x31),
                    ("R50", 0x32), ("R51", 0x33), ("R52", 0x34), ("R53", 0x35), ("R54", 0x36),
                    ("R55", 0x37), ("R56", 0x38), ("R57", 0x39), ("R58", 0x3a), ("R59", 0x3b),
                    ("R60", 0x3c), ("R61", 0x3d), ("R62", 0x3e), ("R63", 0x3f), ("R64", 0x40),
                    ("R65", 0x41), ("R66", 0x42), ("R67", 0x43), ("R68", 0x44), ("R69", 0x45),
                    ("R70", 0x46), ("R71", 0x47), ("R72", 0x48), ("R73", 0x49), ("R74", 0x4a),
                    ("R75", 0x4b), ("R76", 0x4c), ("R77", 0x4d), ("R78", 0x4e), ("R79", 0x4f),
                    ("R80", 0x50), ("R81", 0x51), ("R82", 0x52), ("R83", 0x53), ("R84", 0x54),
                    ("R85", 0x55), ("R86", 0x56), ("R87", 0x57), ("R88", 0x58), ("R89", 0x59),
                    ("R90", 0x5a), ("R91", 0x5b), ("R92", 0x5c), ("R93", 0x5d), ("R94", 0x5e),
                    ("R95", 0x5f), ("R96", 0x60), ("R97", 0x61), ("R98", 0x62), ("R99", 0x63),
                    ("R100", 0x64), ("R101", 0x65), ("R102", 0x66), ("R103", 0x67), ("R104", 0x68),
                    ("R105", 0x69), ("R106", 0x6a), ("R107", 0x6b), ("R108", 0x6c), ("R109", 0x6d),
                    ("R110", 0x6e), ("R111", 0x6f), ("R112", 0x70), ("R113", 0x71), ("R114", 0x72),
                    ("R115", 0x73), ("R116", 0x74), ("R117", 0x75), ("R118", 0x76), ("R119", 0x77),
                    ("R120", 0x78), ("R121", 0x79), ("R122", 0x7a), ("R123", 0x7b), ("R124", 0x7c),
                    ("R125", 0x7d), ("R126", 0x7e), ("R127", 0x7f)])

    INST_LIST = dict([("BREAK", 0x0), ("NOP", 0x1), ("HLT", 0x2), ("STR", 0x3), ("LD", 0x4),
                      ("MOV", 0x5), ("ADD", 0x6), ("SUB", 0x7), ("INC", 0x8), ("DEC", 0x9),
                      ("AND", 0xA), ("OR", 0xB), ("XOR", 0xC), ("NOT", 0xD), ("NOR", 0xE),
                      ("NAND", 0xF), ("XNOR", 0x10), ("SHL", 0x11), ("SHR", 0x12), ("JMP", 0x13),
                      ("PUT", 0x14), ("STC", 0x15), ("CLC", 0x16), ("SWAP", 0x17), ("RD", 0x18),
                      ("WD", 0x19), ("WR", 0x1A), ("CMP", 0x1B), ("JE", 0x1C), ("JNE", 0x1D),
                      ("JG", 0x1E), ("JL", 0x1F), ("JC", 0x20), ("JZ", 0x21), ("CALL", 0x22),
                      ("RET", 0x23), ("IN", 0x24), ("OUT", 0x25), ("CF", 0x26), ("NEG", 0x27)])

    def find_inst(string: str) -> int:
        return INST_LIST.get(string, -1)

    def find_reg(string: str) -> int:
        return REG_LIST.get(string, -1)

    def valid_format(string: str) -> bool:
        return string.isdigit() or \
            (string.startswith("0b") and all(char in "01" for char in string[2:])) or \
            (string.startswith("0x") and all(char in "0123456789ABCDEF" for char in string[2:].upper()))

    line = line.split()
    binary = []

    if not line:
        return binary

    inst = find_inst(line[0].upper())
    if inst == -1:
        if line[0].startswith(';'):
            return binary
        if not line[0].endswith(':'):
            raise ValueError("Invalid instruction.")
        label_name = line[0][:-1]
        if label_name in label:
            raise ValueError("The label is already declared.")
        label[label_name] = code_addr
        return binary
    else:
        binary.append(f"{inst:064b}")

    for i in range(3):
        operand = line[i + 1] if len(line) > i + 1 else ''
        reg = find_reg(operand)
        if reg != -1:
            binary.append(f"{reg:064b}")
        elif valid_format(operand):
            binary.append(f"{int(operand, 0) & 0xFFFFFFFFFFFFFFFF:064b}")
        elif operand in label:
            binary.append(f"{label[operand] & 0xFFFFFFFFFFFFFFFF:064b}")
        else:
            binary.append(f"{0:064b}")

    return binary

def main_assembler():
    if len(sys.argv) < 2:
        print("Usage: python assembler.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = input_file.rsplit('.', 1)[0] + ".bin"
    code_addr: int = 0

    try:
        with open(input_file, "r") as inf, open(output_file, "w") as outf:
            for line_number, line in enumerate(inf, start=1):
                try:
                    binary_line = parse(line, code_addr)
                    if binary_line:
                        outf.write(' '.join(binary_line) + '\n')
                        code_addr += 1
                except ValueError as e:
                    print(f"{output_file}:{line_number}: Error: {e}")
                    sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main_assembler()
