#ifndef FILTER_H
#define FILTER_H

#include <stdio.h>

void filter_message(char *message, size_t msgSize, char (*filter_func)(char));
char upper_filter(char c);
char lower_filter(char c);
char null_filter(char c);

#endif    // FILTER_H
