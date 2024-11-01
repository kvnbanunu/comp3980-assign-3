#include "../include/filter.h"

void filter_message(char *message, size_t msgSize, char (*filter_func)(char))
{
    for(size_t i = 0; i < msgSize && message[i] != '\0'; i++)
    {
        message[i] = filter_func(message[i]);
    }
}

char upper_filter(char c)
{
    if(c >= 'a' && c <= 'z')
    {
        return (char)(c - (char)('a' - 'A'));
    }
    return c;
}

char lower_filter(char c)
{
    if(c >= 'A' && c <= 'Z')
    {
        return (char)(c + (char)('a' - 'A'));
    }
    return c;
}

char null_filter(char c)
{
    return c;
}
