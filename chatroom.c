#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "wrap.h"
#include "data_type.h"
#include "utils.h"

#define DEBUG 1
#define SERV_PORT 8010
#define MAX_CLIENT_SIZE 100
#define MAX_USER_SIZE 1000
#define MAX_BUF_SIZE 100
// SIGN_UP name passwd    size is 3
#define MAX_CMD_SIZE 10

// signal
void handle_signal(int signal);

// 初始化
int init();
struct user ** load_user_from_file(char* path);
struct user * parse_user(char *line);
struct room * load_room_from_file(char* path);

// 请求／回复
int handle_request(int);
void do_message(char*, int, int);
char** parse_cmd(char *buf, int n);
void unparse_cmd(char** cmd);
void response(int fd, int code, const char *msg);

// 未登入的客户端
void print_client_list(struct client *head);
void add_client(struct client *head, int fd, struct sockaddr_in addr);
void remove_client(struct client *head, int fd);
struct client* find_client(int fd);

// 注册/登入/登出
void do_signup(int fd, struct user **users, char *name, char *passwd);
void do_signin(int fd, struct user **users, char *name, char *passwd);
void do_signout(int fd);
void show_user(struct user **users, int len);
struct user* find_user(struct user **users, int id);
int check_signin(int fd);

// 创建/删除/显示 room
void show_room_list(struct room *head);
void do_create_room(int fd, struct room *head, char *name, int limit);
void do_delete_room(int fd, struct room *head, int room_id);
void do_list_room(int fd, struct room *head);
void do_enter_room(int fd, struct room *head, int room_id);
void do_exit_room(int fd, struct room *head, int room_id);
struct room* find_room(struct room *head, int room_id);
void gen_user_list_str(struct user_node *head, char *s);
int get_room_user_count(struct room *r);

// 在自己所在的room中发消息
void do_send_msg(int fd, char *msg);

// 未登录用户链表
static struct client *g_client_head;

// room 链表
static int g_room_id = 0; // 自增id
static struct room *g_room_head;

// user数组
static struct user **g_users;
static int g_user_size = 0;


int main(int argc, char* argv[]) {
    init();

    int listenfd = Socket(AF_INET, SOCK_STREAM, 0);
    printf("listen fd=%d\n", listenfd);

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    // on_exit(handle_signal, (void*)&listenfd);
    // signal(SIGINT, handle_signal);
    
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
                    add_client(g_client_head, clientfd, clientaddr);

                } else {
                    if (handle_request(fd) == 0) {
                        Epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &ev);
                        Close(fd);
                        remove_client(g_client_head, fd);
                        printf("client exit fd=%d\n", fd);
                    }
                }
            }
        }
    }

    return 0;
}

int init() {
    // create head node, fd is -1.
    struct client *c = malloc(sizeof(struct client));
    c->fd = -1;
    c->addr = NULL;
    c->next = NULL;
    g_client_head = c;

    // user
    g_users = load_user_from_file("./db/table_user");
    if (DEBUG) show_user(g_users, g_user_size);

    // room_head
    g_room_head = load_room_from_file("./db/table_room");
    if (DEBUG) show_room_list(g_room_head);
}

struct user ** load_user_from_file(char* path) {
    struct user **arr = malloc(MAX_USER_SIZE * sizeof(struct user*));
    FILE *f = fopen(path, "r");
    int MAX_LEN = 1024; 
    char line[MAX_LEN];
    bzero(line, MAX_LEN);
    while (fgets(line, MAX_LEN, f) != NULL) {
        // 去掉末尾的换行
        line[strnlen(line, MAX_LEN)+1-2] = '\0';
        arr[g_user_size++] = parse_user(line);
    }
    return arr;
}

struct user * parse_user(char *line) {
    struct Node *head = split(line, ';'); 

    // to user
    struct user *one = malloc(sizeof(struct user));
    struct Node *p = head;
    one->id = atoi(p->str);
    p = p->next;
    one->role = atoi(p->str);
    p = p->next;
    strncpy(one->name, p->str, strlen(p->str));
    p = p->next;
    strncpy(one->password, p->str, strlen(p->str));
    
    // free head
    free_split(head);

    return one;
}


struct room * load_room_from_file(char* path) {
    struct room *r = malloc(sizeof(struct room));
    r->id = -1;
    r->next = NULL;

    struct room *rp = r;

    // 0;fuckroom;5;0,1,2,3
    FILE *f = fopen(path, "r");
    int MAX_LEN = 1024; 
    char line[MAX_LEN];
    bzero(line, MAX_LEN);
    while (fgets(line, MAX_LEN, f)) {
        // 去掉末尾的换行
        line[strnlen(line, MAX_LEN)+1-2] = '\0';
        struct Node *head = split(line, ';'); 
        struct room *one = malloc(sizeof(struct room));
        struct Node *p = head;
        // id
        one->id = atoi(p->str);
        if (one->id >= g_room_id) {
            g_room_id = one->id + 1;
        }
        p = p->next;
        // name
        strncpy(one->name, p->str, strlen(p->str));
        p = p->next;
        // limit
        one->limit = atoi(p->str);
        p = p->next;
        // user list
        if (strlen(p->str) > 0) {
            struct user_node *usr_p = NULL;
            struct Node *uid_p = split(p->str, ',');
            while (uid_p) {
                struct user_node *usr_one = malloc(sizeof(struct user_node));
                usr_one->usr = find_user(g_users, atoi(uid_p->str)); 
                usr_one->next = NULL;
                if (usr_p == NULL) {
                    usr_p = usr_one;
                    one->list = usr_p;
                } else {
                    usr_p->next = usr_one;
                    usr_p = usr_p->next;
                }
                uid_p = uid_p->next;
            }
        }
        rp->next = one;
        rp = rp->next;
    }
    return r;
}

void handle_signal(int signal) {
    printf("recv signal is %d....\n", signal);
    exit(0);
}

int handle_request(int fd) {
    char buf[MAX_BUF_SIZE];
    bzero(buf, MAX_BUF_SIZE);
    int n = Read(fd, buf, MAX_BUF_SIZE);
    if (n > 0) {
        do_message(buf, n, fd);
        //Write(fd, resp, n);
    }
    return n;
}

void do_message(char *buf, int n, int fd) {
    char** cmd = parse_cmd(buf, n);
    if (strcmp(cmd[0], "SIGN_UP") == 0) {
        do_signup(fd, g_users, cmd[1], cmd[2]);
    } else if (strcmp(cmd[0], "SIGN_IN") == 0) {
        do_signin(fd, g_users, cmd[1], cmd[2]);
    } else if (strcmp(cmd[0], "SIGN_OUT") == 0) {
        do_signout(fd);

    } else if (strcmp(cmd[0], "CREATE_ROOM") == 0) {
        do_create_room(fd, g_room_head, cmd[1], atoi(cmd[2]));
    } else if (strcmp(cmd[0], "DELETE_ROOM") == 0) {
        do_delete_room(fd, g_room_head, atoi(cmd[1]));
    } else if (strcmp(cmd[0], "LIST_ROOM") == 0) {
        do_list_room(fd, g_room_head);

    } else if (strcmp(cmd[0], "ENTER_ROOM") == 0) {
        do_enter_room(fd, g_room_head, atoi(cmd[1]));
    } else if (strcmp(cmd[0], "EXIT_ROOM") == 0) {
        do_exit_room(fd, g_room_head, atoi(cmd[1]));

    } else if (strcmp(cmd[0], "SEND_MSG") == 0) {
        do_send_msg(fd, cmd[1]);
    } else {
        printf("unknow command!\n");
    }

    unparse_cmd(cmd);
}

void unparse_cmd(char** cmd) {
    for (int i=0; i<MAX_CMD_SIZE; i++) {
        free(cmd[i]);
    }
    free(cmd);
}

char** parse_cmd(char *src, int len) {
    int size = MAX_CMD_SIZE * sizeof(char*);
    char** res = malloc(size);
    bzero(res, size);
    int i = 0;
    char *begin = NULL;
    for (char *p=src; p<(src+len); p++) {
        if (isspace(*p)) {
            if (begin != NULL) {
                int n = p - begin;
                res[i] = malloc(n+1);
                bzero(res[i], n+1);
                strncpy(res[i], begin, n);
                begin = NULL;
                i++;
            }
        } else {
            if (begin == NULL) {
                begin = p;
            }
        }
    }
    to_upper(res[0]);
    return res;
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

void response(int fd, int code, const char *msg) {
    char s[500];
    if (code < 0) {
        sprintf(s, "%s\n", msg);
    } else {
        sprintf(s, "%d %s\n", code, msg);
    }
    Write(fd, s, strlen(s));
}

void do_signup(int fd, struct user **users, char *name, char *passwd) {
    for (int i=0; i<g_user_size; i++) {
        if (strncmp(users[i]->name, name, strlen(users[i]->name)) != 0) {
            response(fd, 400, "user has exist");
            return;
        }
    }

    struct user *p = malloc(sizeof(struct user)); 
    p->id = g_user_size;
    p->role = p->id == 0 ? 0 : 1;
    strncpy(p->name, name, strnlen(name, 100));
    strncpy(p->password, passwd, strnlen(passwd, 100));
    users[g_user_size] = p;
    g_user_size++;

    response(fd, 200, "SIGN_UP success");
}

struct user* find_user(struct user **users, int id) {
    for (int i=0; i<g_user_size; i++) {
        if (users[i]->id == id) {
            return users[i];
        }
    }
    return NULL;
}

void show_user(struct user **users, int len) {
    for (int i=0; i<len; i++) {
        printf("%d %d %s %s\n", users[i]->id, users[i]->role, users[i]->name, users[i]->password);
    }
}

void do_signin(int fd, struct user **users, char *name, char *passwd) {
    char resp_str[100];
    for (int i=0; i<g_user_size; i++) {
        struct user *p = users[i];
        if (strncmp(name, p->name, strlen(p->name)) == 0) {
            if (strncmp(passwd, p->password, strlen(p->password)) == 0) {
                struct client *cli = find_client(fd);
                if (cli == NULL) printf("do_sigin() client not exist");  
                cli->usr = p;

                sprintf(resp_str, "Welcome %s, sign in success.", name);
                response(fd, 200, resp_str); 

            } else {
                sprintf(resp_str, "password is error, %s", name);
                response(fd, 400, resp_str); 
            }
            return;
        } 
    }
    sprintf(resp_str, "%s is not exist, please sign up.", name);
    response(fd, 400, resp_str); 
}

void do_signout(int fd) {
    if (!check_signin(fd)) {
        return;
    }

    struct client *p = find_client(fd);
    char *name = p->usr->name;

    // 如果正呆在某个room内，则先退出房间
    if (p->room != NULL) {
        do_exit_room(fd, g_room_head, p->room->id);
    }
    p->usr = NULL;

    char s[50];
    sprintf(s, "Goodbye %s", name);
    response(fd, 200, s); 
}

int check_signin(int fd) {
    struct client *p = find_client(fd);
    if (p == NULL) {
        response(fd, 500, "No connection");
        return 0;
    }

    if (p->usr == NULL) {
        response(fd, 401, "Not sign in.");
        return 0;
    }

    return 1;
}

struct client * find_client(int fd) {
    struct client *p = g_client_head;
    while (p && (fd != p->fd)) p = p->next;
    return p;
}

void do_create_room(int fd, struct room *head, char *name, int limit) {
    if (!check_signin(fd)) {
        return;
    }

    // 1. 检查权限
    struct client *cli = find_client(fd);
    if (cli->usr->role > 0) {
        response(fd, 400, "Permission denied");
        return;
    }

    // 2. 是否重复
    struct room *h = head->next;
    while (h) {
        if (strncmp(h->name, name, strlen(h->name)) == 0) {
            char s[100];
            sprintf(s, "%s room has exist", name);
            response(fd, 400, s);
            return;
        }
        h = h->next;
    }

    // 3. 添加room到列表
    struct room *r = malloc(sizeof(struct room));
    r->id = g_room_id++; 
    strncpy(r->name, name, strlen(name) + 1);
    r->limit = limit;
    r->list = NULL;
    r->next = NULL;
    
    struct room *p = head;
    while (p && p->next) p = p->next;
    p->next = r;

    char s[100];
    sprintf(s, "create room success, room id is %d", r->id);
    response(fd, 200, s);

    // if (DEBUG) show_room_list(head);
}

void do_delete_room(int fd, struct room *head, int room_id) {
    if (!check_signin(fd)) {
        return;
    }

    // 1. 检查权限
    struct client *cli = find_client(fd);
    if (cli->usr->role > 0) {
        response(fd, 400, "Permission denied");
        return;
    }

    struct room *pre = head;
    struct room *p = head->next;
    while (p) {
        if (p->id == room_id) {
            if (pre) pre->next = p->next; 
            p->next = NULL;
            break;
        }
        pre = p;
        p = p->next;
    }

    if (p == NULL) {
        response(fd, 400, "room id not exist");
        return;
    }

    // 释放前，先让每个人，退出房间
    struct client *cp = g_client_head;
    while (cp) {
        if (room_id == cp->room->id) {
            do_exit_room(cp->fd, g_room_head, room_id);
        }
        cp = cp->next;
    }

    p->list = NULL;
    free(p);
    response(fd, 200, "delete room success");

    // if (DEBUG) show_room_list(head);
}

void show_room_list(struct room *head) {

    struct room *p = head->next;
    while (p) {
        printf("%d %s %d \n", p->id, p->name, p->limit);
        struct user_node *u = p->list;
        while (u) {
            printf("\t(%s)\n", u->usr->name);
            u = u->next;
        }
        p = p->next;
    }

}

int get_room_list_size(struct room *head) {
    int cnt = 0;
    struct room *p = head->next;
    while (p) {
        cnt++;
        p = p->next;
    }
    return cnt;
}

void do_list_room(int fd, struct room *head) {
    if (!check_signin(fd)) {
        return;
    }
    char* buf = malloc(1024);
    bzero(buf, 1024);
    char* s = buf;
    struct room *p = head->next; 
    while (p) {
        char ul[200];
        bzero(ul, 200);
        gen_user_list_str(p->list, ul);
        int len = sprintf(s, "%d %s %d\n%s", p->id, p->name, p->limit, ul);
        s += len;
        p = p->next;
    }


    response(fd, -1, buf);
    free(buf);
}

void gen_user_list_str(struct user_node *head, char *s) {
    struct user_node *u = head;
    while (u) {
        int size = sprintf(s, "\t(%s)\n", u->usr->name);
        s += size;
        u = u->next;
    }
}

int get_room_user_count(struct room *room) {
    int count = 0;
    struct user_node *p = room->list;
    while (p) {
        count++;
        p = p->next;
    }
    return count;
}

void do_enter_room(int fd, struct room *head, int room_id) {
    if (!check_signin(fd)) {
        return;
    }

    char resp[100];
    struct room * p = find_room(head, room_id);
    if (p == NULL) {
        sprintf(resp, "%d room not exist!", room_id);
        response(fd, 400, resp);
        return;
    }

    // room is full
    if (get_room_user_count(p) >= p->limit) {
        response(fd, 400, "room is full");
        return;
    }

    // 只能待在一个room
    struct client *cli = find_client(fd);
    if (cli->room != NULL) {
        sprintf(resp, "You stay in %d room, the first must exit the room!", room_id);
        response(fd, 400, resp);
        return;
    }

    struct user_node *one = malloc(sizeof(struct user_node));
    one->usr = cli->usr;
    one->next = NULL;

    // no body in room
    if (p->list == NULL) {
        p->list = one;
        cli->room = p;
        response(fd, 200,  "enter room success");
        return;
    }

    struct user_node *pre = NULL; 
    struct user_node *node = p->list; 
    while (node) {
        if (node->usr->id == cli->usr->id) {
            response(fd, 200,  "you has in room");
            return;
        } 
        pre = node;
        node = node->next;
    }
    pre->next = one; 

    // 因为每个人只能呆在一个room, 所以每次进入房间，就把room保存在client中
    cli->room = p;
    
    response(fd, 201,  "enter room success");
}

void do_exit_room(int fd, struct room *head, int room_id) {
    if (!check_signin(fd)) {
        return;
    }
    struct client *cli = find_client(fd);
    struct room *r = cli->room;
    struct user_node *pre = NULL;
    struct user_node *p = r->list;
    while (p) {
        if (p->usr->id == cli->usr->id) {
            if (pre) pre->next = p->next;
            if (p == r->list) r->list = p->next;
            p->next = NULL;
            cli->room = NULL;
            response(fd, 200, "exit room success");
            free(p);
            return;
        }
        pre = p;
        p = p->next;
    }
    response(fd, 200, "you not in this room");
    return;
}

struct room* find_room(struct room *head, int room_id) {
    struct room *p = head;
    while (p) {
        if (p->id == room_id) return p;
        p = p->next;
    }
    return NULL;
}

void do_send_msg(int fd, char *msg) {
    if (!check_signin(fd)) {
        return;
    }

    // 获取当前所在room
    struct client *cli = find_client(fd);
    if (cli == NULL || cli->room == NULL) {
        response(fd, 400, "You not in room");
        return;
    }

    struct client *p = g_client_head->next;
    while (p) {
        if (p->room && p->room->id == cli->room->id) {
            response(p->fd, -1, msg);
        }
        p = p->next;
    }
}