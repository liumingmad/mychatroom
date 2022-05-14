
struct room 
{
    int id;
    char name[20];
    int limit;
    struct user *list;
};

struct user
{
    int id;
    int fd;
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
