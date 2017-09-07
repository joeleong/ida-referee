#include <stdio.h>

struct foo {
   int a;
   int b;
};

struct bar {
   struct foo a;
   struct foo *c;
};

struct bar t;

void print(struct bar* p)
{
   if (p->c != NULL)
      printf("%d %d %p %d %d\n", p->a.a, p->a.b, p->c, p->c->a, p->c->b);
   else
      printf("%d %d %p\n", p->a.a, p->a.b, p->c);
}

int main()
{
   struct bar s = {{99, 98}, NULL};
   struct bar *p;
   struct foo f = {0x77, 0x66};
   t.a.a = 1;
   t.c = &f;
   print(&t);
   f.a = 6;
   print(&s);
   int pre = ++s.a.a;
   int post = s.a.a++;
   printf("%d %d\n", pre, post);
   print(&s);
   p = &t;
   print(p);
   t.a.b++;
   t.a.b %= 2;
   t.c->a = 9;
   p->c->b = 5;

   printf("%d %d %p %d %d %p\n",
         t.a.a, t.a.b, t.c, t.c->a, t.c->b, p);
   t.c = NULL;
   p->c = NULL;
   return 0;
}
