typedef enum
  {
    SUB_M6502,
    SUB_M65C02
  }
M6502_SUB_PORT;

typedef struct
  {
    M6502_SUB_PORT sub;
  }
M6502_OPTS;

extern M6502_OPTS m6502_opts;

#define IS_M6502 (m6502_opts.sub == SUB_M6502)
#define IS_M65C02 (m6502_opts.sub == SUB_M65C02)

