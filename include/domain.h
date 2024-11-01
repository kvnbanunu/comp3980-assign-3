#ifndef DOMAIN_H
#define DOMAIN_H

#include <sys/socket.h>

void setup_domain_address(struct sockaddr_storage *addr, socklen_t *addr_len, const char *path);

#endif    // DOMAIN_H
