import sys
from list import *

label = {}

# Replace every tab character with space character
def replace_tabs(string: str) -> str:
    return string.replace('\t', ' ')

# Find valid instruction (Return -1 if not)
def find_inst(string: str) -> int:
    return INST_LIST.__members__.get(string, -1).value if string in INST_LIST.__members__ else -1

# Find valid register (Return -1 if not)
def find_reg(string: str) -> int:
    return REG_LIST.__members__.get(string, -1).value if string in REG_LIST.__members__ else -1

# Check if the operand is used valid format (Binary, Decimal, Hexadecimal)
def valid_format(string: str) -> bool:
    if string.isdigit():
        return True
    if string.startswith("0b") and all(char in "01" for char in string[2:]):
        return True
    if string.startswith("0x") and all(char in "0123456789ABCDEF" for char in string[2:]):
        return True
    return False

# Parse a single line of code
def parse(line: str, code_addr: int) -> list[str]:
    binary = []

    # Break down the line of code
    line = replace_tabs(line.strip()).split()

    if not line:
        # Skip empty line
        return binary

    # Find valid instruction
    inst = find_inst(line[0].upper())
    if inst == -1:
        if line[0].startswith(';'):
            return binary
        if not line[0].endswith(':'):
            raise ValueError(f"Invalid instruction.")
        elif line[0][:-1] in label.keys():
            raise ValueError(f"The label is already declared.")
        else:
            label[line[0][:-1]] = code_addr
        return binary
    else:
        # Append to list
        binary.append(f"{inst:064b}")

    # Process up to 3 operand
    for i in range(3):
        if len(line) <= i + 1 or not line[i + 1]:
            binary.append(f"{0:064b}")
        else:
            operand = line[i + 1]
            reg = find_reg(operand)
            if reg != -1:
                binary.append(f"{reg:064b}")
            elif valid_format(operand):
                binary.append(f"{int(operand, 0) & 0xFFFFFFFFFFFFFFFF:064b}")
            elif operand in label.keys():
                binary.append(f"{label[operand] & 0xFFFFFFFFFFFFFFFF:064b}")
            else:
                raise ValueError(f"Invalid register or undeclared label.")

    return binary

# Main function
def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python assembly.py <input_file>")
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
    main()