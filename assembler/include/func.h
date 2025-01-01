/* func.h */
#ifndef FUNC_H
#define FUNC_H

#include <stdbool.h>

#define MAX_LABELS 100
#define MAX_LABEL_LENGTH 50
#define MAX_FILENAME_LENGTH 255

typedef struct {
    char name[MAX_LABEL_LENGTH];
    int address;
} label_t;

int find_inst(const char *inst);
int find_reg(const char *reg);
bool valid_format(const char *str);
int find_label(const char *label);
void add_label(const char *label, int address);

#endif /* FUNC_H */
