#include <string.h>
#include <stdlib.h>
#include "utils.h"

void itoa(int val, char *s) {
    int i = 0;
    for (int x=val; x>0; x/=10) {
        s[i] = '0' + (x % 10);
        i++;
    }
    reverse(s);
}

void reverse(char *s) {
    char *p1 = s;
    char *p2 = s + strlen(s) - 1;
    while (p1 < p2) {
        char c = *p1;
        *p1 = *p2;
        *p2 = c;
        p1++;
        p2--;
    }
}

struct Node* split(const char *s, char ch) {
    struct Node *head = NULL;
    struct Node *tail = NULL;
    const char *pre = s;
    const char *p = s;
    while (1) {
        if ((*p) == '\0' || (*p) == ch) {
            int size = p - pre + 1;
            struct Node *one = malloc(sizeof(struct Node)); 
            one->next = NULL;
            one->str = malloc(size);
            bzero(one->str, size);
            strncpy(one->str, pre, p-pre);
            if (head == NULL) {
                head = one;
            } else {
                tail->next = one;
            } 
            tail = one;
            if ((*p) == '\0') break;
            if ((*p) == ch) pre = p + 1;
        } 
        p++;
    }
    return head;
}

void free_split(struct Node *head) {
    struct Node *pre = NULL;
    struct Node *p = head;
    while (p) {
        if (pre) free(pre);
        free(p->str);
        pre = p;
        p = p->next;
    }
}

char* to_upper(char *s) {
    char *p = s;
    while ((*p) != '\0') {
        if ((*p) >= 'a' && (*p) <='z') {
            *p -= 'a' - 'A';
        }
        p++;
    }
}