
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
    struct sockaddr_in *addr;
    struct client *next;
};
