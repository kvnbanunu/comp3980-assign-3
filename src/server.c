#include "../include/domain.h"
#include "../include/filter.h"
#include <complex.h>
#include <fcntl.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVER_PATH "/tmp/server_sock"
#define SEM_PATH "/counter_sem"
#define COUNTER_PATH "/counter_mem"
#define BACKLOG 5
#define BUFFER_SIZE 128
#define SEM_PERMS 0644

// Global variables for semaphore
static int                  *connection_counter;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static sem_t                *counter_sem;           // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t exit_flag = 0;         // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static void setup_signal_handler(void);
void        sig_handler(int sig);
int         handle_request(int client_fd);

int main(void)
{
    int                     shm_fd;
    int                     server_fd;
    int                     client_fd;
    int                     result;
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    pid_t                   pid;

    setup_signal_handler();

    setup_domain_address(&addr, &addr_len, SERVER_PATH);

    server_fd = socket(addr.ss_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
    if(server_fd == -1)
    {
        fprintf(stderr, "Error opening socket\n");
        goto fail;
    }

    unlink(SERVER_PATH);    // Remove any existing socket file in the path.
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

    // Set up shared memory for the connection counter
    shm_fd = shm_open(COUNTER_PATH, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if(shm_fd == -1)
    {
        fprintf(stderr, "Error: Failed to open shared memory\n");
        goto fail;
    }

    connection_counter = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, shm_fd, 0);
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
    }
    close(server_fd);
    unlink(SERVER_PATH);
    sem_close(counter_sem);
    sem_unlink(SEM_PATH);
    munmap(connection_counter, sizeof(int));
    unlink(COUNTER_PATH);
    exit(EXIT_SUCCESS);

fail:
    close(server_fd);
    unlink(SERVER_PATH);
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

void sig_handler(int sig)
{
    const char *message = "\nSIGINT received. Server shutting down.\n";
    write(1, message, strlen(message));
    exit_flag = 1;
}

#pragma GCC diagnostic pop

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
