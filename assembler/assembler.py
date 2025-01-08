import sys
from func import *

label = {}

def parse(line: str, code_addr: int):
    binary = []
    line = replace_tabs(line.strip()).split()

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

def main() -> None:
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
                        outf.write(''.join(binary_line) + '\n')
                        code_addr += 1
                except ValueError as e:
                    print(f"{output_file}:{line_number}: Error: {e}")
                    sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
