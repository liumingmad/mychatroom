#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <stdlib.h>

void perr_exit(char* msg) {
    perror(msg);
    exit(1);
}

int Socket(int domain, int type, int protocol) {
    int fd = socket(domain, type, protocol);
    if (fd < 0) {
        perr_exit("socket error");
    }
    return fd;
}

void Bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (bind(sockfd, addr, addrlen) == -1) {
        perr_exit("bind error");
    }
}

void Listen(int sockfd, int backlog) {
    if (listen(sockfd, backlog) == -1) {
        perr_exit("listen error");
    }
}

int Accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    int res = accept(sockfd, addr, addrlen);
    if (res < 0) {
        if (errno == EINTR || errno == ECONNABORTED) {
            Accept(sockfd, addr, addrlen);
        } else {
            perr_exit("accept error");
        }
    }
    return res;
}

int Select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout) {
    int res = select(nfds, readfds, writefds, exceptfds, timeout);
    if (res < 0) {
        if (errno == EINTR || errno == EBADF) {
            return Select(nfds, readfds, writefds, exceptfds, timeout);
        } else {
            perr_exit("select error");
        }
    }
    return res;
}

int Poll(struct pollfd pfds[], nfds_t nfds, int timeout) {
    int res = poll(pfds, nfds, timeout);
    if (res < 0) {
        if (errno == EINTR) {
            return Poll(pfds, nfds, timeout);
        } else {
            perr_exit("poll error");
        }
    }
    return res;
}

int Epoll_create(int size) {
    int res = epoll_create(size); 
    if (res == -1) {
        perr_exit("epoll_create error");
    }
    return res;
}

int Epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    int res = epoll_ctl(epfd, op, fd, event);
    if (res == -1) {
        perr_exit("epoll_ctl error"); 
    }
    return res;
}

int Epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    int res = epoll_wait(epfd, events, maxevents, timeout);
    if (res == -1) {
        if (errno == EINTR) {
            return Epoll_wait(epfd, events, maxevents, timeout);
        } else {
            perr_exit("epoll_wait error");
        }
    }
    return res;
}

int Connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int res = connect(sockfd, addr, addrlen);
    if (res < 0) {
        perr_exit("connect error");
    }
}

ssize_t Read(int fd, void* buf, size_t count) {
    ssize_t n = read(fd, buf, count);
    if (n < 0 && errno == EINTR) {
        return Read(fd, buf, count);
    }
    return n;
}

ssize_t Write(int fd, const void *buf, size_t count) {
    ssize_t n = write(fd, buf, count);
    if (n < 0 && errno == EINTR) {
        return Write(fd, buf, count);
    }
    return n;
}

void Close(int fd) {
    if (close(fd) < 0) {
        perr_exit("close error");
    }
}




