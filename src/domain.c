#include "../include/domain.h"
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>

void setup_domain_address(struct sockaddr_storage *addr, socklen_t *addr_len, const char *path)
{
    struct sockaddr_un *un_addr;

    memset(addr, 0, sizeof(*addr));
    un_addr         = (struct sockaddr_un *)addr;
    addr->ss_family = AF_UNIX;
    strncpy(un_addr->sun_path, path, sizeof(un_addr->sun_path) - 1);
    un_addr->sun_path[sizeof(un_addr->sun_path) - 1] = '\0';
    *addr_len                                        = sizeof(struct sockaddr_un);
}
