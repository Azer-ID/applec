import sys
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import platform
from assembler import *

auto_save_file = None

if platform.system() == "Windows":
    path = os.path.join(os.environ["USERPROFILE"], "Documents")
else:
    path = os.path.join(os.path.expanduser("~"), "Documents")

lines = []

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

        # Set a predefined file name and open the save file dialog
        predefined_name = "output-assembler.bin"
        output_file_path = filedialog.asksaveasfilename(defaultextension=".bin", 
                                                        initialfile=predefined_name,  # Predefined file name
                                                        filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")])
        if output_file_path:
            try:
                # Now call the assembler function to generate the binary file
                code_addr = 0
                with open(auto_save_file, "r") as inf, open(output_file_path, "w") as outf:
                    for line_number, line in enumerate(inf, start=1):
                        try:
                            binary_line = parse(line, code_addr)
                            if binary_line:
                                outf.write(' '.join(binary_line) + '\n')
                                code_addr += 1
                        except ValueError as e:
                            print(f"Error on line {line_number}: {e}")
                            messagebox.showerror("Error", f"Error processing line {line_number}: {e}")
                            return

                # Show a message box with the path to the assembled file
                messagebox.showinfo("Assembled", f"File successfully assembled and saved to:\n{output_file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred during assembly: {e}")



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
