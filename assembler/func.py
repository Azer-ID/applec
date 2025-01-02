from list import *

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
