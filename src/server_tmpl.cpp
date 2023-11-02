// https://www.suchprogramming.com/epoll-in-3-easy-steps/
// https://stackoverflow.com/questions/66916835/c-confused-by-epoll-and-socket-fd-on-linux-systems-and-async-threads
// https://man7.org/linux/man-pages/man7/epoll.7.html

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define PRERF "(errno=%d) %s\n"
#define PREAR(NUM) NUM, strerror(NUM)
#define EPOLL_MAP_TO_NOP (0u)
#define EPOLL_MAP_SHIFT (1u) /* Shift to cover reserved value MAP_TO_NOP */
#define IP_ADDR_SIZE (sizeof("xxx.xxx.xxx.xxx"))

struct client_slot
{
    bool is_used;
    int client_fd;
    char src_ip[IP_ADDR_SIZE];
    uint16_t src_port;
    uint16_t my_index;
};

struct tcp_state
{
    bool stop;
    int tcp_fd;
    int epoll_fd;
    client_slot clients[10];
    /*
     * Map the file descriptor to client_slot array index
     * Note: We assume there is no file descriptor greater than 10000.
     * You must adjust this in production.
     */
    uint32_t client_map[10000];
};

static int my_epoll_add(int epoll_fd, int client_fd, uint32_t events)
{
    epoll_event event;

    /* Shut the valgrind up! */
    memset(&event, 0, sizeof(epoll_event));

    event.events = events;
    event.data.fd = client_fd;

    //setnonblocking(client_fd);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0)
    {
        int err = errno;
        printf("epoll_ctl(EPOLL_CTL_ADD): " PRERF, PREAR(err));
        return -1;
    }
    return 0;
}

static int my_epoll_delete(int epoll_fd, int client_fd)
{
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL) < 0)
    {
        int err = errno;
        printf("epoll_ctl(EPOLL_CTL_DEL): " PRERF, PREAR(err));
        return -1;
    }
    return 0;
}

static const char *convert_addr_ntop(sockaddr_in *addr, char *src_ip_buf)
{
    in_addr_t saddr = addr->sin_addr.s_addr;
    const char * ret = inet_ntop(AF_INET, &saddr, src_ip_buf, IP_ADDR_SIZE);
    if (ret == NULL)
    {
        int err = errno ? errno : EINVAL;
        printf("inet_ntop(): " PRERF, PREAR(err));
    }
    return ret;
}

static int accept_new_client(int tcp_fd, tcp_state *state)
{
    sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));

    int client_fd = accept(tcp_fd, (sockaddr *)&addr, &addr_len);
    if (client_fd < 0)
    {
        int err = errno;
        if (err == EAGAIN) return 0;

        /* Error */
        printf("accept(): " PRERF, PREAR(err));
        return -1;
    }

    char src_ip_buf[IP_ADDR_SIZE];
    uint16_t src_port = ntohs(addr.sin_port);
    const char * src_ip = convert_addr_ntop(&addr, src_ip_buf);
    if (!src_ip)
    {
        printf("Cannot parse source address\n");
        close(client_fd);
        return -1;
    }

    /*
     * Find unused client slot.
     * In real world application, you don't want to iterate
     * the whole array, instead you can use stack data structure
     * to retrieve unused index in O(1).
     */
    const size_t client_slot_num = sizeof(state->clients) / sizeof(*state->clients);
    for (size_t i = 0; i < client_slot_num; i++)
    {
        client_slot * client = &state->clients[i];
        if (!client->is_used)
        {
            /*
             * We found unused slot.
             */
            client->client_fd = client_fd;
            memcpy(client->src_ip, src_ip_buf, sizeof(src_ip_buf));
            client->src_port = src_port;
            client->is_used = true;
            client->my_index = i;

            /*
             * We map the client_fd to client array index that we accept
             * here.
             */
            state->client_map[client_fd] = client->my_index + EPOLL_MAP_SHIFT;

            /*
             * Let's tell to `epoll` to monitor this client file descriptor.
             */
            my_epoll_add(state->epoll_fd, client_fd, EPOLLIN | EPOLLPRI);

            printf("Client %s:%u has been accepted!\n", src_ip, src_port);
            return 0;
        }
    }

    printf("Sorry, can't accept more client at the moment, slot is full\n");
    close(client_fd);
    return -1;
}

static void close_conn(tcp_state *state, client_slot *client, int client_fd)
{
    printf("Client %s:%u has closed its connection\n", client->src_ip, client->src_port);
    my_epoll_delete(state->epoll_fd, client_fd);
    close(client_fd);
    client->is_used = false;
}

static void handle_client_event(int client_fd, uint32_t revents, tcp_state *state)
{
    /*
     * Read the mapped value to get client index.
     */
    uint32_t index = state->client_map[client_fd] - EPOLL_MAP_SHIFT;
    client_slot *client = &state->clients[index];

    const uint32_t err_mask = EPOLLERR | EPOLLHUP;
    if (revents & err_mask)
    {
        close_conn(state, client, client_fd);
        return;
    }

    char buffer[1024];
    ssize_t recv_ret = recv(client_fd, buffer, sizeof(buffer), 0);
    if (recv_ret == 0)
    {
        close_conn(state, client, client_fd);
        return;
    }

    if (recv_ret < 0)
    {
        int err = errno;
        if (err == EAGAIN) return;

        /* Error */
        printf("recv(): " PRERF, PREAR(err));
        close_conn(state, client, client_fd);
        return;
    }

    /*
     * Safe printing
     */
    buffer[recv_ret] = '\0';
    if (buffer[recv_ret - 1] == '\n')
    {
        buffer[recv_ret - 1] = '\0';
    }

    printf("Client %s:%u sent: \"%s\"\n", client->src_ip, client->src_port, buffer);
    return;
}

static int event_loop(tcp_state *state)
{
    int timeout = 10000; /* in milliseconds */
    const int maxevents = 32;
    epoll_event events[32];

    printf("Entering event loop...\n");
    while (!state->stop)
    {
        /*
         * I sleep on `epoll_wait` and the kernel will wake me up
         * when event comes to my monitored file descriptors, or
         * when the timeout reached.
         */
        int epoll_ret = epoll_wait(state->epoll_fd, events, maxevents, timeout);
        if (epoll_ret == 0)
        {
            /*
             *`epoll_wait` reached its timeout
             */
            printf("No events within %d ms\n", timeout);
            continue;
        }

        if (epoll_ret == -1)
        {
            int err = errno;
            if (err == EINTR)
            {
                printf("Something interrupted me!\n");
                continue;
            }

            /* Error */
            printf("epoll_wait(): " PRERF, PREAR(err));
            return -1;
        }

        for (int i = 0; i < epoll_ret; i++)
        {
            int fd = events[i].data.fd;
            if (fd == state->tcp_fd)
            {
                /*
                 * A new client is connecting to us...
                 */
                accept_new_client(fd, state);
            } else {
                /*
                 * We have event(s) from client, let's call `recv()` to read it.
                 */
                handle_client_event(fd, events[i].events, state);
            }
        }
    }

    return 0;
}

static int init_epoll(tcp_state *state)
{
    printf("Initializing epoll_fd...\n");

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
    {
        int err = errno;
        printf("epoll_create(): " PRERF, PREAR(err));
        return -1;
    }

    state->epoll_fd = epoll_fd;
    return 0;
}

static int init_socket(tcp_state *state)
{
    int ret;
    sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    const char *bind_addr = "0.0.0.0";
    uint16_t bind_port = 1234;

    printf("Creating TCP socket...\n");
    int tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (tcp_fd < 0)
    {
        int err = errno;
        printf("socket(): " PRERF, PREAR(err));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bind_port);
    addr.sin_addr.s_addr = inet_addr(bind_addr);

    ret = bind(tcp_fd, (sockaddr*)&addr, addr_len);
    if (ret < 0)
    {
        int err = errno;
        printf("bind(): " PRERF, PREAR(err));
        close(tcp_fd);
        return -1;
    }

    ret = listen(tcp_fd, 10);
    if (ret < 0)
    {
        int err = errno;
        printf("listen(): " PRERF, PREAR(err));
        close(tcp_fd);
        return -1;
    }

    /*
     * Add `tcp_fd` to epoll monitoring.
     * If epoll returned tcp_fd in `events` then a client is
     * trying to connect to us.
     */
    ret = my_epoll_add(state->epoll_fd, tcp_fd, EPOLLIN | EPOLLPRI);
    if (ret < 0)
    {
        close(tcp_fd);
        return -1;
    }

    printf("Listening on %s:%u...\n", bind_addr, bind_port);
    state->tcp_fd = tcp_fd;
    return 0;
}

static void init_state(tcp_state *state)
{
    const size_t client_slot_num = sizeof(state->clients) / sizeof(*state->clients);
    const size_t client_map_num = sizeof(state->client_map) / sizeof(*state->client_map);

    for (size_t i = 0; i < client_slot_num; i++)
    {
        state->clients[i].is_used = false;
        state->clients[i].client_fd = -1;
    }

    for (size_t i = 0; i < client_map_num; i++)
    {
        state->client_map[i] = EPOLL_MAP_TO_NOP;
    }
}

int main(void)
{
    int ret;
    tcp_state state;

    init_state(&state);

    ret = init_epoll(&state);
    if (ret != 0) return 1;

    ret = init_socket(&state);
    if (ret != 0) return 1;

    state.stop = false;

    ret = event_loop(&state);

    return ret;
}
