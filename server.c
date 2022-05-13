#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <netinet/in.h>

#include "wrap.h"

#define SERV_PORT 8010
#define MAX_CLIENT_SIZE 100
#define MAX_BUF_SIZE 100

int hendle_request(int);
void do_message(char*);


struct room 
{
    int id;
    char name[20];
    int limit;
    struct user *head;
    struct room *next;
};

struct user
{
    int id;
    int role;
    char name[20];
    char password[100];
    struct user *next;
};

struct client {
    int fd;
    struct client *next;
};

void add_client(struct client *head, int fd) {

}

void remove_client(struct client *head, int fd) {
    
}


int main(int argc, char* argv[]) {
    struct client *client_head = NULL;
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
        printf("epoll wait count=%d\n", count);
        for (int i=0; i<count; i++) {
            struct epoll_event *one = evlist + i;
            if (one->events & EPOLLIN) {
                int fd = one->data.fd;
                if (listenfd == fd) {
                    struct sockaddr_in clientaddr;
                    socklen_t len = sizeof(clientaddr);
                    int clientfd = Accept(fd, (struct sockaddr*)&clientaddr, &len);

                    struct epoll_event ev;
                    ev.events = EPOLLIN;
                    ev.data.fd = clientfd;
                    Epoll_ctl(epfd, EPOLL_CTL_ADD, clientfd, &ev);

                } else {
                    if (hendle_request(fd) == 0) {
                        Epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
                        Close(fd);
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