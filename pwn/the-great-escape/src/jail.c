// gcc jail.c -o jail -lseccomp

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>

#define ESCAPE_PLAN_LEN 128

typedef void (*escape_plan_t)();

void enable_jail()
{
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);

  seccomp_load(ctx);
}

int main(int argc, char** argv)
{
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);

  escape_plan_t escape_plan = (escape_plan_t)mmap(NULL, ESCAPE_PLAN_LEN,
      PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

  if (escape_plan == NULL) {
    return 1;
  }

  printf("what is your escape plan?\n > ");
  fgets((char*)escape_plan, ESCAPE_PLAN_LEN - 1, stdin);

  enable_jail();
  escape_plan();

  return 0;
}

