#include <string.h>
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