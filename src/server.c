/*
 * Kevin Nguyen
 * A00955925
 */

#include "../include/filter.h"
#include "../include/socket.h"
#include <arpa/inet.h>
#include <complex.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SEM_PATH "/counter_sem"
#define COUNTER_PATH "/counter_mem"
#define UNKNOWN_OPTION_MESSAGE_LEN 24
#define BASE_TEN 10
#define BUFFER_SIZE 128
#define SEM_PERMS 0644
#define SHM_PERMS 0600

// Global variables for semaphore
static int                  *connection_counter;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static sem_t                *counter_sem;           // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t exit_flag = 0;         // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static void           setup_signal_handler(void);
static void           sig_handler(int sig);
static void           parse_arguments(int argc, char *argv[], char **ip_address, char **port);
static void           handle_arguments(const char *binary_name, const char *ip_address, const char *port_str, in_port_t *port);
static in_port_t      parse_in_port_t(const char *binary_name, const char *port_str);
_Noreturn static void print_usage(const char *program_name, int exit_code, const char *message);
static void           socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port);
int                   handle_request(int client_fd);

int main(int argc, char *argv[])
{
    int                     shm_fd;
    int                     server_fd;
    int                     client_fd;
    int                     result;
    struct sockaddr_storage addr;
    pid_t                   pid;
    in_port_t               port;
    char                   *address  = NULL;
    char                   *port_str = NULL;

    setup_signal_handler();
    parse_arguments(argc, argv, &address, &port_str);
    handle_arguments(argv[0], address, port_str, &port);
    convert_address(address, &addr);
    server_fd = socket_create(addr.ss_family, SOCK_STREAM, 0);
    socket_bind(server_fd, &addr, port);

    result = listen(server_fd, SOMAXCONN);
    if(result == -1)
    {
        fprintf(stderr, "Error listening");
        goto fail;
    }

    printf("Server listening on %s:%s for requests...\n", address, port_str);

    // Set up shared memory for the connection counter
    shm_fd = shm_open(COUNTER_PATH, O_CREAT | O_RDWR, SHM_PERMS);
    if(shm_fd == -1)
    {
        fprintf(stderr, "Error: Failed to open shared memory\n");
        goto fail;
    }

    ftruncate(shm_fd, sizeof(int));

    connection_counter = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if(connection_counter == MAP_FAILED)
    {
        fprintf(stderr, "Error: mmap failed\n");
        close(shm_fd);
        goto fail;
    }
    *connection_counter = 0;    // Initialize counter to 0

    // Init semaphore for counter protection
    counter_sem = sem_open(SEM_PATH, O_CREAT, SEM_PERMS, 1);
    if(counter_sem == SEM_FAILED)
    {
        fprintf(stderr, "Error: sem_open failed\n");
        close(shm_fd);
        munmap(connection_counter, sizeof(int));
        goto fail;
    }

    while(!(exit_flag))
    {
        client_fd = accept(server_fd, NULL, 0);
        if(client_fd == -1)
        {
            if(exit_flag)
            {
                break;
            }
            continue;
        }

        printf("Request recieved. Processing...\n");

        pid = fork();
        if(pid < 0)
        {
            perror("fork");
            close(client_fd);
            if(exit_flag)
            {
                break;
            }
            continue;
        }
        if(pid == 0)
        {
            close(server_fd);
            if(handle_request(client_fd) == -1)
            {
                fprintf(stderr, "Could not handle request\n");
                exit(EXIT_FAILURE);
            }
            printf("Request processed. Sending response...\n");

            // Increment connection counter in a critical section
            sem_wait(counter_sem);                                       // lock semaphore
            (*connection_counter)++;                                     // update counter
            printf("Sent request number: %d\n", *connection_counter);    // Access counter
            sem_post(counter_sem);                                       // unlock semaphore

            exit(EXIT_SUCCESS);
        }
        close(client_fd);
        if(exit_flag)
        {
            break;
        }
    }
    close(server_fd);
    close(shm_fd);
    sem_close(counter_sem);
    sem_unlink(SEM_PATH);
    munmap(connection_counter, sizeof(int));
    unlink(COUNTER_PATH);
    exit(EXIT_SUCCESS);

fail:
    close(server_fd);
    sem_unlink(SEM_PATH);
    unlink(COUNTER_PATH);
    exit(EXIT_FAILURE);
}

static void setup_signal_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
#if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
    sa.sa_handler = sig_handler;
#if defined(__clang__)
    #pragma clang diagnostic pop
#endif
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static void sig_handler(int sig)
{
    const char *message = "\nSIGINT received. Server shutting down.\n";
    write(1, message, strlen(message));
    exit_flag = 1;
}

#pragma GCC diagnostic pop

static void parse_arguments(int argc, char *argv[], char **ip_address, char **port)
{
    int opt;
    opterr = 0;

    while((opt = getopt(argc, argv, "h")) != -1)
    {
        switch(opt)
        {
            case 'h':
            {
                print_usage(argv[0], EXIT_SUCCESS, NULL);
            }
            case '?':
            {
                char message[UNKNOWN_OPTION_MESSAGE_LEN];

                snprintf(message, sizeof(message), "Unknown option '-%c'.", optopt);
                print_usage(argv[0], EXIT_FAILURE, NULL);
            }
            default:
            {
                print_usage(argv[0], EXIT_FAILURE, NULL);
            }
        }
    }

    if(optind >= argc)
    {
        print_usage(argv[0], EXIT_FAILURE, "Error: the ip address and port are required");
    }

    if(optind + 1 >= argc)
    {
        print_usage(argv[0], EXIT_FAILURE, "Error: the port is required");
    }

    if(optind < argc - 2)
    {
        print_usage(argv[0], EXIT_FAILURE, "Error: too many arugments.");
    }

    *ip_address = argv[optind];
    *port       = argv[optind + 1];
}

static void handle_arguments(const char *binary_name, const char *ip_address, const char *port_str, in_port_t *port)
{
    if(ip_address == NULL)
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: the ip address is required");
    }

    if(port_str == NULL)
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: the port is required");
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
        perror("Error parsing port");
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        print_usage(binary_name, EXIT_FAILURE, "Error: Invalid characters in input");
    }

    // Check if the parsed value is within the valid range
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
    fprintf(stderr, "Usage: %s [-h] <ip address> <port>\n", program_name);
    fputs("Options:\n", stderr);
    fputs("\t-h Display this help message\n", stderr);
    exit(exit_code);
}

static void socket_bind(int sockfd, struct sockaddr_storage *addr, in_port_t port)
{
    char      addr_str[INET6_ADDRSTRLEN];
    socklen_t addr_len;
    void     *vaddr;
    in_port_t net_port;

    net_port = htons(port);

    if(addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        addr_len            = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        vaddr               = (void *)&(((struct sockaddr_in *)addr)->sin_addr);
    }
    else if(addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        addr_len             = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        vaddr                = (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr);
    }
    else
    {
        fprintf(stderr, "Internal error: addr->ss_family must be AF_INET or AF_INET6, was: %d\n", addr->ss_family);
        exit(EXIT_FAILURE);
    }

    if(inet_ntop(addr->ss_family, vaddr, addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    if(bind(sockfd, (struct sockaddr *)addr, addr_len) == -1)
    {
        perror("Binding failed");
        fprintf(stderr, "Error code: %d\n", errno);
        exit(EXIT_FAILURE);
    }
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
