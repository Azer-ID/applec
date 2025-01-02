import sys
from enum import Enum
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import platform

auto_save_file = None

if platform.system() == "Windows":
    path = os.path.join(os.environ["USERPROFILE"], "Documents")
else:
    path = os.path.join(os.path.expanduser("~"), "Documents")

lines = []
label = {}

def parse(line, code_addr: int):
    REG_LIST = dict([
        ("R0", 0x0),
        ("R1", 0x1),
        ("R2", 0x2),
        ("R3", 0x3),
        ("R4", 0x4),
        ("R5", 0x5),
        ("R6", 0x6),
        ("R7", 0x7),
        ("R8", 0x8),
        ("R9", 0x9),
        ("R10", 0xA),
        ("R11", 0xB),
        ("R12", 0xC),
        ("R13", 0xD),
        ("R14", 0xE),
        ("R15", 0xF)
    ])

    INST_LIST = dict([
        ("BREAK", 0x0),
        ("NOP", 0x1),
        ("HLT", 0x2),
        ("STR", 0x3),
        ("LD", 0x4),
        ("MOV", 0x5),
        ("ADD", 0x6),
        ("SUB", 0x7),
        ("INC", 0x8),
        ("DEC", 0x9),
        ("AND", 0xA),
        ("OR", 0xB),
        ("XOR", 0xC),
        ("NOT", 0xD),
        ("NOR", 0xE),
        ("NAND", 0xF),
        ("XNOR", 0x10),
        ("SHL", 0x11),
        ("SHR", 0x12),
        ("JMP", 0x13),
        ("PUT", 0x14),
        ("STC", 0x15),
        ("CLC", 0x16),
        ("SWAP", 0x17),
        ("RD", 0x18),
        ("WD", 0x19),
        ("WR", 0x1A),
        ("CMP", 0x1B),
        ("JE", 0x1C),
        ("JNE", 0x1D),
        ("JG", 0x1E),
        ("JL", 0x1F),
        ("JC", 0x20),
        ("JZ", 0x21),
        ("CALL", 0x22),
        ("RET", 0x23),
        ("IN", 0x24),
        ("OUT", 0x25),
        ("CF", 0x26),
        ("NEG", 0x27)
    ])

    def replace_tabs(string: str) -> str:
        return string.replace('\t', ' ')

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
    global auto_save_file
    code_addr = 0
    if not auto_save_file or not os.path.exists(auto_save_file):
        print("Error: Auto-save file does not exist.")
        return

    try:
        output_file = os.path.join(path, "output-assembler.bin")
        with open(auto_save_file, "r") as inf, open(output_file, "w") as outf:
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

class LineBasedEditor:
    def __init__(self, root):
        global auto_save_file
        self.root = root
        self.root.title("Line-Based Text Editor (Lines as List)")
        self.lines = []
        self.auto_save_path = self.get_documents_path()

        if not os.path.exists(self.auto_save_path):
            os.makedirs(self.auto_save_path)

        auto_save_file = os.path.join(self.auto_save_path, "autosave.txt")
        self.auto_save_enabled = False  # Auto-save disabled

        self.text_area = tk.Text(self.root, wrap='none', undo=True)
        self.text_area.pack(fill=tk.BOTH, expand=1)

        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(fill=tk.X)

        self.assemble_button = tk.Button(self.button_frame, text="Assemble", command=self.save_and_assemble)
        self.assemble_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.save_button = tk.Button(self.button_frame, text="Save", command=self.save_file)
        self.save_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.open_button = tk.Button(self.button_frame, text="Open", command=self.open_file)
        self.open_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.clear_button = tk.Button(self.button_frame, text="Clear", command=self.clear_text)
        self.clear_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def get_documents_path(self):
        if platform.system() == "Windows":
            return os.path.join(os.environ["USERPROFILE"], "Documents")
        else:
            return os.path.join(os.path.expanduser("~"), "Documents")

    def save_and_assemble(self):
        content = self.text_area.get(1.0, tk.END).strip()
        self.lines = content.split("\n")

        # Save content to the auto-save file
        with open(auto_save_file, "w") as file:
            for line in self.lines:
                file.write(line + "\n")

        # Now call the assembler function to generate the binary file
        main_assembler()

    def save_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                                 filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "w") as file:
                for line in self.lines:
                    file.write(line + "\n")
            messagebox.showinfo("Saved", f"File saved to {file_path}")

    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "r") as file:
                self.lines = [line.strip() for line in file.readlines()]
            self.refresh_text_area()
            messagebox.showinfo("Opened", f"File loaded from {file_path}")

    def refresh_text_area(self):
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(1.0, "\n".join(self.lines))

    def clear_text(self):
        self.text_area.delete(1.0, tk.END)
        self.lines = []
        messagebox.showinfo("Cleared", "Text area and lines list cleared!")

    def on_closing(self):
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    editor = LineBasedEditor(root)
    root.geometry("800x600")
    root.mainloop()
