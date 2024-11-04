/*
 * Kevin Nguyen
 * A00955925
 */

#include "../include/socket.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10
#define MAX_ARGS 6    // [program, opt, filter, message, address, port]

static void           parse_arguments(int argc, char *argv[], char **target_address, char **port, char **filter, char **message);
static void           handle_arguments(const char *binary_name, const char *target_address, const char *port_str, in_port_t *port, const char *filter, const char *message);
static in_port_t      parse_in_port_t(const char *binary_name, const char *str);
_Noreturn static void print_usage(const char *program_name, int exit_code, const char *message);
static void           socket_connect(int sockfd, struct sockaddr_storage *addr, in_port_t port);
static void           shutdown_socket(int sockfd, int how);
static void           socket_close(int sockfd);

int main(int argc, char *argv[])
{
    int                     server_fd;
    size_t                  msg_size;
    ssize_t                 bytes_read;
    struct sockaddr_storage addr;
    in_port_t               port;
    char                   *filter   = NULL;
    char                   *message  = NULL;
    char                   *address  = NULL;
    char                   *port_str = NULL;
    char                   *buffer;
    char                   *message_received;

    parse_arguments(argc, argv, &address, &port_str, &filter, &message);
    handle_arguments(argv[0], address, port_str, &port, filter, message);
    convert_address(address, &addr);
    server_fd = socket_create(addr.ss_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
    socket_connect(server_fd, &addr, port);

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
    shutdown_socket(server_fd, SHUT_WR);
    socket_close(server_fd);
    exit(EXIT_SUCCESS);
}

static void parse_arguments(int argc, char *argv[], char **target_address, char **port, char **filter, char **message)
{
    int opt;

    opterr = 0;

    while((opt = getopt(argc, argv, "hf:")) != -1)
    {
        switch(opt)
        {
            case 'h':
            {
                print_usage(argv[0], EXIT_SUCCESS, NULL);
            }
            case '?':
            {
                char optmessage[UNKNOWN_OPTION_MESSAGE_LEN];

                snprintf(optmessage, sizeof(optmessage), "Unknown option '-%c'.", optopt);
                print_usage(argv[0], EXIT_FAILURE, optmessage);
            }
            case 'f':
            {
                *filter = optarg;
                break;
            }
            default:
            {
                print_usage(argv[0], EXIT_FAILURE, "Error: Invalid option flag");
            }
        }
    }

    if(optind >= argc)
    {
        print_usage(argv[0], EXIT_FAILURE, "Error: Unexpected arguments");
    }

    if(argc > MAX_ARGS)
    {
        print_usage(argv[0], EXIT_FAILURE, "Error: Too many arguments");
    }

    *message        = argv[optind];
    *target_address = argv[optind + 1];
    *port           = argv[optind + 2];
}

static void handle_arguments(const char *binary_name, const char *target_address, const char *port_str, in_port_t *port, const char *filter, const char *message)
{
    if(target_address == NULL)
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: Target address is required");
    }

    if(port_str == NULL)
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: Port is required");
    }

    if(filter == NULL)
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: Filter cannot be null");
    }

    if(!(strcmp(filter, "U") == 0 || strcmp(filter, "L") == 0 || strcmp(filter, "N") == 0))
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: Invalid filter option");
    }

    if(strlen(filter) != 1)
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: Filter option needs to be a single char");
    }

    if(message == NULL)
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: Message cannot be null");
    }

    *port = parse_in_port_t(binary_name, port_str);
}

static in_port_t parse_in_port_t(const char *binary_name, const char *str)
{
    char     *endptr;
    uintmax_t parsed_value;

    errno        = 0;
    parsed_value = strtoumax(str, &endptr, BASE_TEN);

    if(errno != 0)
    {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: Invalid characters in input");
    }

    // Check if the parsed value is within the valid range for in_port_t
    if(parsed_value > UINT16_MAX)
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: port value out of range");
    }

    return (in_port_t)parsed_value;
}

_Noreturn static void print_usage(const char *program_name, int exit_code, const char *message)
{
    if(message)
    {
        fprintf(stderr, "%s\n", message);
    }

    fprintf(stderr, "Usage: %s -f <U|L|N> <message> <target address> <port>\n", program_name);
    fputs("Options:\n", stderr);
    fputs("\t-h Display this help message\n", stderr);
    fputs("\t-f <U|L|N>:\n\tU = Uppercase\n\tL = Lowercase\n\tN = No Change\n", stderr);
    exit(exit_code);
}

static void socket_connect(int sockfd, struct sockaddr_storage *addr, in_port_t port)
{
    char      addr_str[INET6_ADDRSTRLEN];
    in_port_t net_port;
    socklen_t addr_len;

    if(inet_ntop(addr->ss_family, addr->ss_family == AF_INET ? (void *)&(((struct sockaddr_in *)addr)->sin_addr) : (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr), addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Connecting to: %s:%u\n", addr_str, port);
    net_port = htons(port);

    if(addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        ipv4_addr->sin_port = net_port;
        addr_len            = sizeof(struct sockaddr_in);
    }
    else if(addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        ipv6_addr->sin6_port = net_port;
        addr_len             = sizeof(struct sockaddr_in6);
    }
    else
    {
        fprintf(stderr, "Invalid address family: %d\n", addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if(connect(sockfd, (struct sockaddr *)addr, addr_len) == -1)
    {
        const char *msg;

        msg = strerror(errno);
        fprintf(stderr, "Error: connect (%d): %s\n", errno, msg);
        exit(EXIT_FAILURE);
    }

    printf("Connected to: %s:%u\n", addr_str, port);
}

static void shutdown_socket(int sockfd, int how)
{
    if(shutdown(sockfd, how) == -1)
    {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}

static void socket_close(int sockfd)
{
    if(close(sockfd) == -1)
    {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
}
