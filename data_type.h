
struct room 
{
    int id;
    char name[20];
    int limit;
    struct user_node *list;
    struct room *next;
};

struct user_node {
    struct user *usr;
    struct user_node *next;
};

struct user
{
    int id;
    int role;
    char name[20];
    char password[100];
};

struct client {
    int fd;
    struct user *usr;
    struct room *room;
    struct sockaddr_in *addr;
    struct client *next;
};
