#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>

void convert_address(const char *address, struct sockaddr_storage *addr);
int  socket_create(int domain, int type, int protocol);

#endif    // SOCKET_H
