/*
 * Kevin Nguyen
 * A00955925
 */

#include "../include/filter.h"

/* Applies filter to each character based on function pointer */
void filter_message(char *message, size_t msgSize, char (*filter_func)(char))
{
    for(size_t i = 0; i < msgSize && message[i] != '\0'; i++)
    {
        message[i] = filter_func(message[i]);
    }
}

/* Converts char to uppercase */
char upper_filter(char c)
{
    if(c >= 'a' && c <= 'z')
    {
        return (char)(c - (char)('a' - 'A'));
    }
    return c;
}

/* Converts char to lowercase */
char lower_filter(char c)
{
    if(c >= 'A' && c <= 'Z')
    {
        return (char)(c + (char)('a' - 'A'));
    }
    return c;
}

/* Returns char with no change */
char null_filter(char c)
{
    return c;
}
