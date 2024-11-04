/*
 * Kevin Nguyen
 * A00955925
 */

#include "../include/domain.h"
#include "../include/usage.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVER_PATH "/tmp/server_sock"
#define MAX_ARGS 4    // [program, opt, filter, message]

int main(int argc, char *argv[])
{
    int                     server_fd;
    int                     opt;
    size_t                  msg_size;
    ssize_t                 bytes_read;
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    const char             *filter  = NULL;
    const char             *message = NULL;
    char                   *buffer;
    char                   *message_received;

    while((opt = getopt(argc, argv, "f:")) != -1)
    {
        if(opt == 'f')
        {
            filter = optarg;
        }
        else
        {
            fprintf(stderr, "Error: Invalid option flag %d\n", opt);
            print_usage(argv[0]);
            goto fail;
        }
    }

    if(filter == NULL)
    {
        fprintf(stderr, "Error: Filter cannot be null\n");
        print_usage(argv[0]);
        goto fail;
    }

    if(strlen(filter) != 1)
    {
        fprintf(stderr, "Error: Filter option needs to be a single char\n");
        print_usage(argv[0]);
        goto fail;
    }

    if(!(strcmp(filter, "U") == 0 || strcmp(filter, "L") == 0 || strcmp(filter, "N") == 0))
    {
        fprintf(stderr, "Error: Invalid filter option%s\n", filter);
        print_usage(argv[0]);
        goto fail;
    }

    if(optind >= argc)
    {
        fprintf(stderr, "Error: Unexpected arguments\n");
        print_usage(argv[0]);
        goto fail;
    }

    if(argc > MAX_ARGS)
    {
        fprintf(stderr, "Error: Too many arguments\n");
        print_usage(argv[0]);
        goto fail;
    }

    message = argv[optind];
    if(message == NULL)
    {
        fprintf(stderr, "Error: Message cannot be null\n");
        print_usage(argv[0]);
        goto fail;
    }

    setup_domain_address(&addr, &addr_len, SERVER_PATH);

    server_fd = socket(addr.ss_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
    if(server_fd == -1)
    {
        fprintf(stderr, "Error: Opening socket\n");
        goto fail;
    }

    if(connect(server_fd, (struct sockaddr *)&addr, addr_len))
    {
        fprintf(stderr, "Error: Could not connect to server\n");
        goto cleanup;
    }

    msg_size = (size_t)snprintf(NULL, 0, "%s\n%s", filter, message) + 1;
    buffer   = (char *)malloc(msg_size);
    if(buffer == NULL)
    {
        fprintf(stderr, "Error: Malloc buffer\n");
        goto cleanup;
    }
    snprintf(buffer, msg_size, "%s\n%s", filter, message);

    printf("Sending message to server...\n");

    if(write(server_fd, buffer, msg_size - 1) < 0)
    {
        fprintf(stderr, "Error: Message could not be sent\n");
        goto free_buffer;
    }

    message_received = (char *)malloc(strlen(message) + 1);
    if(message_received == NULL)
    {
        fprintf(stderr, "Error: Malloc message_received\n");
        goto free_buffer;
    }

    bytes_read = read(server_fd, message_received, strlen(message) + 1);
    if(bytes_read == -1)
    {
        fprintf(stderr, "Error: Could not read from server\n");
        goto free_message_received;
    }

    printf("Message received from Server: %s\n", message_received);

free_message_received:
    free(message_received);

free_buffer:
    free(buffer);

cleanup:
    close(server_fd);
    exit(EXIT_SUCCESS);

fail:
    exit(EXIT_FAILURE);
}
