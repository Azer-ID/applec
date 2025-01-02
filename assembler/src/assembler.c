/* assembler.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "func.h"

#define MAX_LINE_LENGTH 256
#define BINARY_LENGTH 64

void parse(const char *line, int code_addr, FILE *outf, uint32_t line_count) {
    char *line_copy = strdup(line);
    if (!line_copy) {
        perror("Error duplicating line");
        exit(EXIT_FAILURE);
    }

    char *token = strtok(line_copy, " \t\n");
    if (!token) {
        free(line_copy);
        return;
    }

    int inst = find_inst(token);
    if (inst == -1) {
        if (token[0] == ';') {
            free(line_copy);
            return;
        }
        if (token[strlen(token) - 1] != ':') {
            fprintf(stderr, "Error on line %u: Invalid instruction.\n", line_count);
            free(line_copy);
            exit(EXIT_FAILURE);
        }

        char label_name[MAX_LABEL_LENGTH];
        strncpy(label_name, token, strlen(token) - 1);
        label_name[strlen(token) - 1] = '\0';

        if (find_label(label_name) != -1) {
            fprintf(stderr, "Error at line %u: Label already declared.\n", line_count);
            free(line_copy);
            exit(EXIT_FAILURE);
        }

        add_label(label_name, code_addr);
        free(line_copy);
        return;
    }

    char binary[BINARY_LENGTH + 1] = {0};
    snprintf(binary, sizeof(binary), "%016s", ""); 

    for (int i = 15; i >= 0; --i) {
        binary[15 - i] = ((inst >> i) & 1) + '0';
    }

    for (int i = 0; i < 3; ++i) {
        token = strtok(NULL, " \t\n");
        char operand_binary[17] = {0};
        if (!token) {
            snprintf(operand_binary, sizeof(operand_binary), "%016s", "0000000000000000");
            strncat(binary, operand_binary, sizeof(binary) - strlen(binary) - 1);
            continue;
        }

        int reg = find_reg(token);
        if (reg != -1) {
            for (int j = 15; j >= 0; --j) {
                operand_binary[15 - j] = ((reg >> j) & 1) + '0';
            }
        } else if (valid_format(token)) {
            unsigned long value = strtoul(token, NULL, 0);
            for (int j = 15; j >= 0; --j) {
                operand_binary[15 - j] = ((value >> j) & 1) + '0';
            }
        } else {
            int label_addr = find_label(token);
            if (label_addr == -1) {
                fprintf(stderr, "Error on line %u: Undefined label '%s'.\n", line_count, token);
                free(line_copy);
                exit(EXIT_FAILURE);
            }
            for (int j = 15; j >= 0; --j) {
                operand_binary[15 - j] = ((label_addr >> j) & 1) + '0';
            }
        }
        strncat(binary, operand_binary, sizeof(binary) - strlen(binary) - 1);
    }

    fprintf(outf, "%s\n", binary);
    free(line_copy);
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *inf = fopen(argv[1], "r");
    if (!inf) {
        perror("Error opening input file");
        return EXIT_FAILURE;
    }

    char output_file[MAX_FILENAME_LENGTH];
    snprintf(output_file, sizeof(output_file), "%s.bin", strtok(argv[1], "."));

    FILE *outf = fopen(output_file, "w");
    if (!outf) {
        perror("Error opening output file");
        fclose(inf);
        return EXIT_FAILURE;
    }

    char line[MAX_LINE_LENGTH];
    int code_addr = 0;
    uint32_t line_count = 0;
    while (fgets(line, sizeof(line), inf)) {
        ++line_count;
        parse(line, code_addr, outf, line_count);
        ++code_addr;
    }

    fclose(inf);
    fclose(outf);
    return EXIT_SUCCESS;
}
