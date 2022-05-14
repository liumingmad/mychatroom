
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
    int online;         // for SIGN_IN/SIGN_OUT
};

struct client {
    int fd;
    struct user *usr;
    struct sockaddr_in *addr;
    struct client *next;
};
