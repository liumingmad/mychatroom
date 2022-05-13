#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "wrap.h"
#include "data_type.h"

#define DEBUG 1
#define SERV_PORT 8010
#define MAX_CLIENT_SIZE 100
#define MAX_BUF_SIZE 100

int hendle_request(int);
void do_message(char*);

void print_client_list(struct client *head);
void add_client(struct client *head, int fd, struct sockaddr_in addr);
void remove_client(struct client *head, int fd);


int main(int argc, char* argv[]) {
    // create head node, fd is -1.
    struct client *c = malloc(sizeof(struct client));
    c->fd = -1;
    c->next = NULL;
    struct client *client_head = c;

    struct room *room_head = NULL;
    struct user users[100];


    int listenfd = Socket(AF_INET, SOCK_STREAM, 0);
    printf("listen fd=%d\n", listenfd);
    
    struct sockaddr_in servaddr;
    bzero((void*)&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SERV_PORT);
    Bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    Listen(listenfd, 5);

    int epfd = Epoll_create(1);

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listenfd;
    Epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);

    struct  epoll_event evlist[MAX_CLIENT_SIZE];
    
    while (1) {
        int count = Epoll_wait(epfd, evlist, MAX_CLIENT_SIZE, -1);
        for (int i=0; i<count; i++) {
            struct epoll_event *one = evlist + i;
            if (one->events & EPOLLIN) {
                int fd = one->data.fd;
                if (listenfd == fd) {
                    struct sockaddr_in clientaddr;
                    socklen_t len = sizeof(clientaddr);
                    int clientfd = Accept(fd, (struct sockaddr*)&clientaddr, &len);
                    printf("enter clientfd %d\n", clientfd);

                    struct epoll_event ev;
                    ev.events = EPOLLIN;
                    ev.data.fd = clientfd;
                    Epoll_ctl(epfd, EPOLL_CTL_ADD, clientfd, &ev);
                    add_client(client_head, clientfd, clientaddr);

                } else {
                    if (hendle_request(fd) == 0) {
                        Epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
                        Close(fd);
                        remove_client(client_head, fd);
                        printf("client exit fd=%d\n", fd);
                    }
                }
            }
        }
    }

    return 0;
}

int hendle_request(int fd) {
    char buf[MAX_BUF_SIZE];
    bzero(buf, MAX_BUF_SIZE);
    int n = Read(fd, buf, MAX_BUF_SIZE);
    if (n > 0) {
        do_message(buf);
        Write(fd, buf, n);
    }
    return n;
}

void do_message(char *buf) {
    for (char *p=buf; *p; p++) {
        *p = toupper(*p);
    }
}

void add_client(struct client *head, int fd, struct sockaddr_in addr) {
    struct client *c = malloc(sizeof(struct client));
    c->fd = fd;
    c->next = NULL;
    int size = sizeof(struct sockaddr_in);
    c->addr = malloc(size);
    memcpy(c->addr, &addr, size);

    struct client *p = head;
    while (p->next) {
        p = p->next;
    } 
    p->next = c;

    if (DEBUG) print_client_list(head);
}

void remove_client(struct client *head, int fd) {
    struct client *pre = NULL;
    struct client *p = head;
    while (p) {
        if (p->fd == fd) {
            if (pre) pre->next = p->next;
            p->next = NULL;
            free(p->addr);
            free(p);
            break;
        }
        pre = p;
        p = p->next;
    }

    if (DEBUG) print_client_list(head);
}

void print_client_list(struct client *head) {
    struct client *p = head->next;
    while (p) {
        char str[INET_ADDRSTRLEN];
        const char *host = inet_ntop(AF_INET, &(p->addr->sin_addr), str, sizeof(str));
        int port = ntohs(p->addr->sin_port);
        printf("(%d %s:%d)-->\n", p->fd, host, port);
        p = p->next;
    }
}