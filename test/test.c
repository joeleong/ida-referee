#include <stdio.h>

struct test {
   int a;
   int b;
   int c;
};

struct test t;

void print(struct test* p) 
{
   printf("%d %d %d\n", p->a, p->b, p->c);
}

int main()
{
   struct test *p;
   t.a = 1;
   t.b = 2;
   t.c = 3;
   print(&t);

   p = &t;
   printf("%d %d %d %p\n", t.a, t.b, t.c, p);
   p->c = 4;
   int *ip =(int*)(((char*)p)+4);
   *ip += 22;
   ip++;
   *ip += 33;

   printf("%d %d %d %p %p %d\n", t.a, t.b, t.c, p, ip, *ip);
   return 0;
}
