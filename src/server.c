#include "../include/domain.h"
#include "../include/filter.h"
#include <complex.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVER_PATH "/tmp/server.sock"
#define BACKLOG 5
#define BUFFER_SIZE 128

void sig_handler(int sig);
int  handle_request(int client_fd);

int main(void)
{
    int                     server_fd;
    int                     client_fd;
    int                     result;
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    pid_t                   pid;

    signal(SIGINT, sig_handler);

    setup_domain_address(&addr, &addr_len, SERVER_PATH);

    server_fd = socket(addr.ss_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
    if(server_fd == -1)
    {
        fprintf(stderr, "Error opening socket\n");
        goto fail;
    }

    result = bind(server_fd, (const struct sockaddr *)&addr, addr_len);
    if(result == -1)
    {
        fprintf(stderr, "Error binding domain socket");
        goto fail;
    }

    result = listen(server_fd, BACKLOG);
    if(result == -1)
    {
        fprintf(stderr, "Error listening");
        goto fail;
    }

    printf("Server listening for requests...\n");

    while(1)
    {
        client_fd = accept(server_fd, NULL, 0);
        if(client_fd == -1)
        {
            perror("accept");
            goto fail;
        }

        printf("Request recieved\n");

        pid = fork();
        if(pid < 0)
        {
            perror("fork");
            close(client_fd);
        }
        if(pid == 0)
        {
            close(server_fd);
            if(handle_request(client_fd) == -1)
            {
                fprintf(stderr, "Could not handle request\n");
            }
            else
            {
                printf("Request handled successfully\n");
            }
            exit(EXIT_SUCCESS);
        }
    }

fail:
    close(server_fd);
    unlink(SERVER_PATH);
    exit(EXIT_FAILURE);
}

void sig_handler(int sig)
{
    (void)sig;
    unlink(SERVER_PATH);
    exit(EXIT_SUCCESS);
}

int handle_request(int client_fd)
{
    char        buf[BUFFER_SIZE];
    const char *filter;
    int         retval;
    char       *message;
    char       *state;
    char (*filter_func)(char) = NULL;
    ssize_t bytesRead         = read(client_fd, buf, BUFFER_SIZE - 1);
    if(bytesRead == -1)
    {
        fprintf(stderr, "Error: couldn't read from client\n");
        retval = -1;
        goto cleanup;
    }
    buf[bytesRead] = '\0';

    filter  = strtok_r(buf, "\n", &state);
    message = strtok_r(NULL, "\n", &state);

    if(filter == NULL)
    {
        fprintf(stderr, "Error: Filter cannot be null\n");
        retval = -1;
        goto cleanup;
    }

    if(strcmp(filter, "U") == 0)
    {
        filter_func = upper_filter;
    }
    else if(strcmp(filter, "L") == 0)
    {
        filter_func = lower_filter;
    }
    else if(strcmp(filter, "N") == 0)
    {
        filter_func = null_filter;
    }
    else
    {
        fprintf(stderr, "Error: invalid filter flag\n");
        retval = -1;
        goto cleanup;
    }

    filter_message(message, BUFFER_SIZE, filter_func);

    if(write(client_fd, message, BUFFER_SIZE - 1) == -1)
    {
        fprintf(stderr, "Error writing to client\n");
        retval = -1;
        goto cleanup;
    }

    retval = 0;
cleanup:
    close(client_fd);
    return retval;
}
