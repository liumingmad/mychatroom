#include <sys/socket.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/epoll.h>

void perr_exit(char* msg);

int Socket(int domain, int type, int protocol);

void Bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

void Listen(int sockfd, int backlog);

int Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int Select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout); 

int Poll(struct pollfd pfds[], nfds_t nfds, int timeout);

int Epoll_create(int size);

int Epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int Epoll_wait(int epfd, struct epoll_event *events,
                      int maxevents, int timeout);

int Connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

ssize_t Read(int fd, void* buf, size_t count);

ssize_t Write(int fd, const void *buf, size_t count);

void Close(int fd);