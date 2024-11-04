/*
 * Kevin Nguyen
 * A00955925
 */

#include "../include/usage.h"
#include <stdio.h>

void print_usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s -f <U|L|N> <string>\n", prog_name);
    fprintf(stderr, "\t-f <U|L|N>:\n\tU = Uppercase\n\tL = Lowercase\n\tN = No Change\n");
}
