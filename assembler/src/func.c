/* func.c */
#include "func.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

static label_t labels[MAX_LABELS];
static int label_count = 0;

static const char *INST_LIST[] = {
    "BREAK", "NOP", "HLT", "STR", "LD", "MOV", "ADD", "SUB", "INC", "DEC",
    "AND", "OR", "XOR", "NOT", "NOR", "NAND", "XNOR", "SHL", "SHR", "JMP",
    "PUT", "STC", "CLC", "SWAP", "RD", "WD", "WR", "CMP", "JE", "JNE",
    "JG", "JL", "JC", "JZ", "CALL", "RET", "IN", "OUT", "CF", "NEG"
};

static const char *REG_LIST[] = {
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9",
    "R10", "R11", "R12", "R13", "R14", "R15"
};

int find_inst(const char *str) {
    for (int i = 0; i < (sizeof(INST_LIST) / sizeof(INST_LIST[0])); ++i) {
        if (strcasecmp(str, INST_LIST[i]) == 0) {
            return i;
        }
    }
    return -1;
}

int find_reg(const char *reg) {
    for (int i = 0; i < (sizeof(REG_LIST) / sizeof(REG_LIST[0])); ++i) {
        if (strcasecmp(reg, REG_LIST[i]) == 0) {
            return i;
        }
    }
    return -1;
}

bool valid_format(const char *str) {
    if (isdigit(str[0])) return true;
    if (strncmp(str, "0b", 2) == 0) {
        for (size_t i = 2; i < strlen(str); ++i) {
            if (str[i] != '0' && str[i] != '1') return false;
        }
        return true;
    }
    if (strncmp(str, "0x", 2) == 0) {
        for (size_t i = 2; i < strlen(str); ++i) {
            if (!isxdigit(str[i])) return false;
        }
        return true;
    }
    return false;
}

int find_label(const char *label) {
    for (int i = 0; i < label_count; ++i) {
        if (strcmp(labels[i].name, label) == 0) {
            return labels[i].address;
        }
    }
    return -1;
}

void add_label(const char *label, int address) {
    if (label_count >= MAX_LABELS) {
        fprintf(stderr, "Error: Maximum label count exceeded.\n");
        exit(EXIT_FAILURE);
    }

    strncpy(labels[label_count].name, label, MAX_LABEL_LENGTH - 1);
    labels[label_count].name[MAX_LABEL_LENGTH - 1] = '\0';
    labels[label_count].address = address;
    ++label_count;
}
