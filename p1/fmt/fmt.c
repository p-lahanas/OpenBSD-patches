#include <stdio.h>
#include <errno.h>
#include <util.h>

int
main(int argc, char *argv[])
{
    char buf[FMT_SCALED_STRSIZE];
    long long ninput = 10483892;
  
    /* Scale according to multiple of a Bytes (e.g. MB)*/
    if (fmt_scaled(ninput, buf) == 0)
    printf("%lld -> %s\n", ninput, buf);
  
    else
    fprintf(stderr, "fmt scaled failed (errno %d)", errno);
 
    return (0);
}
