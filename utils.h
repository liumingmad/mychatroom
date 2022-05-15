
void itoa(int val, char *s);

void reverse(char *s);

struct Node {
    char *str;
    struct Node *next;
};
struct Node* split(const char *s, char c);
void free_split(struct Node *head);

char* to_upper(char *s);