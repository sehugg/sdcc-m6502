
// sim65 constants
#define SYS_args  0xfff0
#define SYS_exit  0xfff1
#define SYS_open  0xfff2
#define SYS_close 0xfff3
#define SYS_read  0xfff4
#define SYS_write 0xfff5

static unsigned char chout;

typedef void (*sim65_write_t)(int count, const char* buf, int fd) __reentrant;

void
_putchar(unsigned char c)
{
  chout = c;
  (*(sim65_write_t)SYS_write)(1, &chout, 1);
}

void
_initEmu(void)
{
}

void
_exitEmu(void)
{
  __asm
    jsr 0xfff1
  __endasm;
}
