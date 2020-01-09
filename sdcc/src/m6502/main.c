/*-------------------------------------------------------------------------
  main.h - m6502 specific general function

  Copyright (C) 2003, Erik Petrich

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the
  Free Software Foundation; either version 2, or (at your option) any
  later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
-------------------------------------------------------------------------*/
/*
    Note that mlh prepended _m6502_ on the static functions.  Makes
    it easier to set a breakpoint using the debugger.
*/
#include "common.h"
#include "m6502.h"
#include "main.h"
#include "ralloc.h"
#include "gen.h"
#include "dbuf_string.h"

extern char * iComments2;
extern DEBUGFILE dwarf2DebugFile;
extern int dwarf2FinalizeFile(FILE *);

static char _m6502_defaultRules[] =
{
#include "peeph.rul"
};

static char _m65c02_defaultRules[] =
{
#include "peeph.rul"
};

M6502_OPTS m6502_opts;

/* list of key words used by msc51 */
static char *_m6502_keywords[] =
{
  "at",
  //"bit",
  "code",
  "critical",
  "data",
  "far",
  //"idata",
  "interrupt",
  "near",
  //"pdata",
  "reentrant",
  //"sfr",
  //"sbit",
  //"using",
  "xdata",
  "_data",
  "_code",
  "_generic",
  "_near",
  "_xdata",
  //"_pdata",
  //"_idata",
  "_naked",
  "_overlay",
  NULL
};


void m6502_assignRegisters (ebbIndex *);

static int regParmFlg = 0;      /* determine if we can register a parameter */

static void
_m6502_init (void)
{
  m6502_opts.sub = SUB_M6502;
  asm_addTree (&asm_asxxxx_mapping);
}

static void
_m65c02_init (void)
{
  m6502_opts.sub = SUB_M65C02;
  asm_addTree (&asm_asxxxx_mapping);
}

static void
_m6502_reset_regparm (struct sym_link *funcType)
{
  regParmFlg = 0;
}

static int
_m6502_regparm (sym_link * l, bool reentrant)
{
  int size = getSize(l);

  /* If they fit completely, the first two bytes of parameters can go */
  /* into A and X, otherwise, they go on the stack. Examples:         */
  /*   foo(char p1)                    A <- p1                        */
  /*   foo(char p1, char p2)           A <- p1, X <- p2               */
  /*   foo(char p1, char p2, char p3)  A <- p1, X <- p2, stack <- p3  */
  /*   foo(int p1)                     XA <- p1                       */
  /*   foo(long p1)                    stack <- p1                    */
  /*   foo(char p1, int p2)            A <- p1, stack <- p2           */
  /*   foo(int p1, char p2)            XA <- p1, stack <- p2          */

  if (regParmFlg>=2)
    return 0;

  if ((regParmFlg+size)>2)
    {
      regParmFlg = 2;
      return 0;
    }

  regParmFlg += size;
  return 1+regParmFlg-size;
}

static bool
_m6502_parseOptions (int *pargc, char **argv, int *i)
{
  if (!strcmp (argv[*i], "--out-fmt-elf"))
    {
      options.out_fmt = 'E';
      debugFile = &dwarf2DebugFile;
      return TRUE;
    }

  if (!strcmp (argv[*i], "--oldralloc"))
    {
      options.oldralloc = TRUE;
      return TRUE;
    }

  return FALSE;
}

#define OPTION_SMALL_MODEL          "--model-small"
#define OPTION_LARGE_MODEL          "--model-large"

static OPTION _m6502_options[] =
  {
    {0, OPTION_SMALL_MODEL, NULL, "8-bit address space for data"},
    {0, OPTION_LARGE_MODEL, NULL, "16-bit address space for data (default)"},
    {0, "--out-fmt-elf", NULL, "Output executable in ELF format" },
    {0, "--oldralloc", NULL, "Use old register allocator"},
    {0, NULL }
  };

static void
_m6502_finaliseOptions (void)
{
  if (options.noXinitOpt)
    port->genXINIT = 0;

  if (options.model == MODEL_LARGE) {
      port->mem.default_local_map = xdata;
      port->mem.default_globl_map = xdata;
    }
  else
    {
      port->mem.default_local_map = data;
      port->mem.default_globl_map = data;
    }

  istack->ptrType = FPOINTER;
}

static void
_m6502_setDefaultOptions (void)
{
  options.code_loc = 0x8000;
  options.data_loc = 0x80;
  options.xdata_loc = 0;        /* 0 means immediately following data */
  options.stack_loc = 0x1ff;
  options.out_fmt = 's';        /* use motorola S19 output */

  options.omitFramePtr = 1;     /* no frame pointer (we use SP */
                                /* offsets instead)            */
}

static const char *
_m6502_getRegName (const struct reg_info *reg)
{
  if (reg)
    return reg->name;
  return "err";
}

static void
_m6502_genAssemblerPreamble (FILE * of)
{
  int i;
  int needOrg = 1;
  symbol *mainExists=newSymbol("main", 0);
  mainExists->block=0;

  fprintf (of, "\t.area %s\n",HOME_NAME);
  fprintf (of, "\t.area GSINIT0 (CODE)\n");
  fprintf (of, "\t.area %s\n",port->mem.static_name);
  fprintf (of, "\t.area %s\n",port->mem.post_static_name);
  fprintf (of, "\t.area %s\n",CODE_NAME);
  fprintf (of, "\t.area %s\n",port->mem.xinit_name);
  fprintf (of, "\t.area %s\n",port->mem.const_name);
  fprintf (of, "\t.area %s\n",port->mem.data_name);
  fprintf (of, "\t.globl __TEMP\n");
  fprintf (of, "__TEMP:\t.ds 4\n");
  fprintf (of, "\t.area %s\n",port->mem.overlay_name);
  fprintf (of, "\t.area %s\n",port->mem.xdata_name);
  fprintf (of, "\t.area %s\n",port->mem.xidata_name);

  if ((mainExists=findSymWithLevel(SymbolTab, mainExists)))
    {
      // generate interrupt vector table
      fprintf (of, "\t.area\tCODEIVT (ABS)\n");

      for (i=maxInterrupts;i>0;i--)
        {
          if (interrupts[i])
            {
              if (needOrg)
                {
                  fprintf (of, "\t.org\t0x%04x\n", (0xfffe - (i * 2)));
                  needOrg = 0;
                }
              fprintf (of, "\t.dw\t%s\n", interrupts[i]->rname);
            }
          else
            needOrg = 1;
        }
      if (needOrg)
        fprintf (of, "\t.org\t0xfffe\n");
      fprintf (of, "\t.dw\t%s", "__sdcc_gs_init_startup\n\n");

      fprintf (of, "\t.area GSINIT0\n");
      fprintf (of, "__sdcc_gs_init_startup:\n");
      if (options.stack_loc)
        {
          fprintf (of, "\tldx\t#0x%02x\n", options.stack_loc & 0xff);
          fprintf (of, "\ttxs\n");
        }
      else
        fprintf (of, "\trsp\n");
      fprintf (of, "\tjsr\t__sdcc_external_startup\n");
      fprintf (of, "\tbeq\t__sdcc_init_data\n");
      fprintf (of, "\tjmp\t__sdcc_program_startup\n");
      fprintf (of, "__sdcc_init_data:\n");

      // TODO: what if l_XINIT > 255?
      fprintf (of, "; _m6502_genXINIT() start\n");
      fprintf (of, "        ldx  #0\n");
      fprintf (of, "00001$:\n");
      fprintf (of, "        cpx  #l_XINIT\n");
      fprintf (of, "        beq  00002$\n");
      fprintf (of, "        lda  s_XINIT,x\n");
      fprintf (of, "        sta  s_XISEG,x\n");
      fprintf (of, "        inx\n");
      fprintf (of, "        bne  00001$\n");
      fprintf (of, "00002$:\n");
      fprintf (of, "; _m6502_genXINIT() end\n");

      fprintf (of, "\t.area GSFINAL\n");
      fprintf (of, "\tjmp\t__sdcc_program_startup\n\n");

      fprintf (of, "\t.area CSEG\n");
      fprintf (of, "__sdcc_program_startup:\n");
      fprintf (of, "\tjsr\t_main\n");
      fprintf (of, "\tjmp\t.\n");

    }
}

static void
_m6502_genAssemblerEnd (FILE * of)
{
  if (options.out_fmt == 'E' && options.debug)
    {
      dwarf2FinalizeFile (of);
    }
}

static void
_m6502_genExtraAreas (FILE * asmFile, bool mainExists)
{
    fprintf (asmFile, "%s", iComments2);
    fprintf (asmFile, "; extended address mode data\n");
    fprintf (asmFile, "%s", iComments2);
    dbuf_write_and_destroy (&xdata->oBuf, asmFile);
}

/* Generate interrupt vector table. */
static int
_m6502_genIVT (struct dbuf_s * oBuf, symbol ** interrupts, int maxInterrupts)
{
  int i;

  dbuf_printf (oBuf, "\t.area\tCODEIVT (ABS)\n");
  dbuf_printf (oBuf, "\t.org\t0x%04x\n",
    (0xfffe - (maxInterrupts * 2)));

  for (i=maxInterrupts;i>0;i--)
    {
      if (interrupts[i])
        dbuf_printf (oBuf, "\t.dw\t%s\n", interrupts[i]->rname);
      else
        dbuf_printf (oBuf, "\t.dw\t0xffff\n");
    }
  dbuf_printf (oBuf, "\t.dw\t%s", "__sdcc_gs_init_startup\n");

  return TRUE;
}

/* Generate code to copy XINIT to XISEG */
static void _m6502_genXINIT (FILE * of) {
  fprintf (of, ";       _m6502_genXINIT() start\n");
  fprintf (of, ";       _m6502_genXINIT() end\n");
}


/* Do CSE estimation */
static bool cseCostEstimation (iCode *ic, iCode *pdic)
{
    operand *result = IC_RESULT(ic);
    sym_link *result_type = operandType(result);

    /* if it is a pointer then return ok for now */
    if (IC_RESULT(ic) && IS_PTR(result_type)) return 1;

    if (ic->op == ADDRESS_OF)
      return 0;

    /* if bitwise | add & subtract then no since m6502 is pretty good at it
       so we will cse only if they are local (i.e. both ic & pdic belong to
       the same basic block */
    if (IS_BITWISE_OP(ic) || ic->op == '+' || ic->op == '-') {
        /* then if they are the same Basic block then ok */
        if (ic->eBBlockNum == pdic->eBBlockNum) return 1;
        else return 0;
    }

    /* for others it is cheaper to do the cse */
    return 1;
}

/* Indicate which extended bit operations this port supports */
static bool
hasExtBitOp (int op, int size)
{
  if (op == RRC
      || op == RLC
      //|| (op == SWAP && size <= 2)
      // TODO?
      //|| op == GETABIT
      //|| op == GETBYTE
      //|| op == GETWORD
     )
    return TRUE;
  else
    return FALSE;
}

/* Indicate the expense of an access to an output storage class */
static int
oclsExpense (struct memmap *oclass)
{
  if (IN_DIRSPACE (oclass))     /* direct addressing mode is fastest */
    return -2;
  if (IN_FARSPACE (oclass))     /* extended addressing mode is almost at fast */
    return -1;
  if (oclass == istack)         /* stack is the slowest */
    return 2;

  return 0; /* anything we missed */
}

/*----------------------------------------------------------------------*/
/* m6502_dwarfRegNum - return the DWARF register number for a register.  */
/*   These are defined for the M6502 in "Motorola 8- and 16-bit Embedded */
/*   Application Binary Interface (M8/16EABI)"                          */
/*----------------------------------------------------------------------*/
static int
m6502_dwarfRegNum (const struct reg_info *reg)
{
  switch (reg->rIdx)
    {
    case A_IDX: return 0;
    case H_IDX: return 1;
    case X_IDX: return 2;
    case CND_IDX: return 17;
    case SP_IDX: return 15;
    }
  return -1;
}

static bool
_hasNativeMulFor (iCode *ic, sym_link *left, sym_link *right)
{
  return FALSE;
}

typedef struct asmLineNode
  {
    int size;
  }
asmLineNode;

static asmLineNode *
newAsmLineNode (void)
{
  asmLineNode *aln;

  aln = Safe_alloc ( sizeof (asmLineNode));
  aln->size = 0;

  return aln;
}

typedef struct m6502opcodedata
  {
    char name[6];
    char adrmode;
    /* info for registers used and/or modified by an instruction will be added here */
  }
m6502opcodedata;

#define M6502OP_STD 1
#define M6502OP_RMW 2
#define M6502OP_INH 3
#define M6502OP_IM1 4
#define M6502OP_BR 5
#define M6502OP_BTB 6
#define M6502OP_BSC 7
#define M6502OP_MOV 8
#define M6502OP_CBEQ 9
#define M6502OP_CPHX 10
#define M6502OP_LDHX 11
#define M6502OP_STHX 12
#define M6502OP_DBNZ 13

/* These must be kept sorted by opcode name */
static m6502opcodedata m6502opcodeDataTable[] =
  {
    {".db",   M6502OP_INH}, /* used by the code generator only in the jump table */
    {"adc",   M6502OP_STD},
    {"ais",   M6502OP_IM1},
    {"aix",   M6502OP_IM1},
    {"and",   M6502OP_STD},
    {"asl",   M6502OP_RMW},
    {"asla",  M6502OP_INH},
    {"aslx",  M6502OP_INH},
    {"asr",   M6502OP_RMW},
    {"asra",  M6502OP_INH},
    {"asrx",  M6502OP_INH},
    {"bcc",   M6502OP_BR,},
    {"bclr",  M6502OP_BSC},
    {"bcs",   M6502OP_BR},
    {"beq",   M6502OP_BR},
    {"bge",   M6502OP_BR},
    {"bgnd",  M6502OP_INH},
    {"bgt",   M6502OP_BR},
    {"bhcc",  M6502OP_BR},
    {"bhcs",  M6502OP_BR},
    {"bhi",   M6502OP_BR},
    {"bhs",   M6502OP_BR},
    {"bih",   M6502OP_BR},
    {"bil",   M6502OP_BR},
    {"bit",   M6502OP_STD},
    {"ble",   M6502OP_BR},
    {"blo",   M6502OP_BR},
    {"bls",   M6502OP_BR},
    {"blt",   M6502OP_BR},
    {"bmc",   M6502OP_BR},
    {"bmi",   M6502OP_BR},
    {"bms",   M6502OP_BR},
    {"bne",   M6502OP_BR},
    {"bpl",   M6502OP_BR},
    {"bra",   M6502OP_BR},
    {"brclr", M6502OP_BTB},
    {"brn",   M6502OP_BR},
    {"brset", M6502OP_BTB},
    {"bset",  M6502OP_BSC},
    {"bsr",   M6502OP_BR},
    {"cbeq",  M6502OP_CBEQ},
    {"cbeqa", M6502OP_CBEQ},
    {"cbeqx", M6502OP_CBEQ},
    {"clc",   M6502OP_INH},
    {"cli",   M6502OP_INH},
    {"clr",   M6502OP_RMW},
    {"clra",  M6502OP_INH},
    {"clrh",  M6502OP_INH},
    {"clrx",  M6502OP_INH},
    {"cmp",   M6502OP_STD},
    {"com",   M6502OP_RMW},
    {"coma",  M6502OP_INH},
    {"comx",  M6502OP_INH},
    {"cphx",  M6502OP_CPHX},
    {"cpx",   M6502OP_STD},
    {"daa",   M6502OP_INH},
    {"dbnz",  M6502OP_DBNZ},
    {"dbnza", M6502OP_BR},
    {"dbnzx", M6502OP_BR},
    {"dec",   M6502OP_RMW},
    {"deca",  M6502OP_INH},
    {"decx",  M6502OP_INH},
    {"div",   M6502OP_INH},
    {"eor",   M6502OP_STD},
    {"inc",   M6502OP_RMW},
    {"inca",  M6502OP_INH},
    {"incx",  M6502OP_INH},
    {"jmp",   M6502OP_STD},
    {"jsr",   M6502OP_STD},
    {"lda",   M6502OP_STD},
    {"ldhx",  M6502OP_LDHX},
    {"ldx",   M6502OP_STD},
    {"lsl",   M6502OP_RMW},
    {"lsla",  M6502OP_INH},
    {"lslx",  M6502OP_INH},
    {"lsr",   M6502OP_RMW},
    {"lsra",  M6502OP_INH},
    {"lsrx",  M6502OP_INH},
    {"mov",   M6502OP_MOV},
    {"mul",   M6502OP_INH},
    {"neg",   M6502OP_RMW},
    {"nega",  M6502OP_INH},
    {"negx",  M6502OP_INH},
    {"nop",   M6502OP_INH},
    {"nsa",   M6502OP_INH},
    {"ora",   M6502OP_STD},
    {"pha",   M6502OP_INH},
    {"phy",   M6502OP_INH},
    {"phx",   M6502OP_INH},
    {"pla",   M6502OP_INH},
    {"ply",   M6502OP_INH},
    {"plx",   M6502OP_INH},
    {"rol",   M6502OP_RMW},
    {"rola",  M6502OP_INH},
    {"rolx",  M6502OP_INH},
    {"ror",   M6502OP_RMW},
    {"rora",  M6502OP_INH},
    {"rorx",  M6502OP_INH},
    {"rsp",   M6502OP_INH},
    {"rti",   M6502OP_INH},
    {"rts",   M6502OP_INH},
    {"sbc",   M6502OP_STD},
    {"sec",   M6502OP_INH},
    {"sei",   M6502OP_INH},
    {"sta",   M6502OP_STD},
    {"sthx",  M6502OP_STHX},
    {"stop",  M6502OP_INH},
    {"stx",   M6502OP_STD},
    {"stz",   M6502OP_STD},
    {"swi",   M6502OP_INH},
    {"tap",   M6502OP_INH},
    {"tax",   M6502OP_INH},
    {"tpa",   M6502OP_INH},
    {"tst",   M6502OP_RMW},
    {"tsta",  M6502OP_INH},
    {"tstx",  M6502OP_INH},
    {"tsx",   M6502OP_INH},
    {"txa",   M6502OP_INH},
    {"txs",   M6502OP_INH},
    {"wait",  M6502OP_INH}
  };

static int
m6502_opcodeCompare (const void *key, const void *member)
{
  return strcmp((const char *)key, ((m6502opcodedata *)member)->name);
}

/*--------------------------------------------------------------------*/
/* Given an instruction and its first two operands, compute the       */
/* instruction size. There are a few cases where it's too complicated */
/* to distinguish between an 8-bit offset and 16-bit offset; in these */
/* cases we conservatively assume the 16-bit offset size.             */
/*--------------------------------------------------------------------*/
static int
m6502_instructionSize(const char *inst, const char *op1, const char *op2)
{
  m6502opcodedata *opcode;
  int size;
  long offset;
  char * endnum = NULL;
  
  opcode = bsearch (inst, m6502opcodeDataTable,
                    sizeof(m6502opcodeDataTable)/sizeof(m6502opcodedata),
                    sizeof(m6502opcodedata), m6502_opcodeCompare);

  if (!opcode)
    return 999;
  switch (opcode->adrmode)
    {
      case M6502OP_INH: /* Inherent addressing mode */
        return 1;
        
      case M6502OP_BSC: /* Bit set/clear direct addressing mode */
      case M6502OP_BR:  /* Branch (1 byte signed offset) */
      case M6502OP_IM1: /* 1 byte immediate addressing mode */
        return 2;
        
      case M6502OP_BTB:  /* Bit test direct addressing mode and branch */
        return 3;
        
      case M6502OP_RMW: /* read/modify/write instructions */
        if (!op2[0]) /* if not ,x or ,sp must be direct addressing mode */
          return 2;
        if (!op1[0])  /* if ,x with no offset */
          return 1;
        if (op2[0] == 'x')  /* if ,x with offset */
          return 2;
        if (!strcmp(op1, "a"))  /* accumulator */
          return 1;
        return 3;  /* Otherwise, must be ,sp with offset */
        
      case M6502OP_STD: /* standard instruction */
        if (!op2[0])
          {
            if (op1[0] == '#') /* Immediate addressing mode */
              return 2;
            if (op1[0] == '*') /* Direct addressing mode */
              return 2;
            return 3; /* Otherwise, must be extended addressing mode */
          }
        else
          {
            if (!op1[0]) /* if ,x with no offset */
              return 1;
            size = 2;
            if (op2[0] == 's')
              size++;
            offset = strtol (op1, &endnum, 0) & 0xffff;
            if (endnum && *endnum)
              size++;
            else if (offset > 0xff)
              size++;
            return size;
          }
      case M6502OP_MOV:
        if (op2[0] == 'x')
          return 2;
        return 3;
      case M6502OP_CBEQ:
        if (op2[0] == 'x' && !op1[0])
          return 2;  /* cbeq ,x+,rel */
        if (op2[0] == 's')
          return 4;  /* cbeq oprx8,sp,rel */
        return 3;
      case M6502OP_CPHX:
        if (op1[0] == '*')
          return 2;
        return 3;
      case M6502OP_DBNZ:
        if (!op2[0])
          return 2;
        if (!op1[0] && op2[0] == 'x')
          return 2;
        if (op2[0] == 's')
          return 4;
        return 3;
      case M6502OP_LDHX:
      case M6502OP_STHX:
        if (op1[0] == '*')
          return 2;
        if (!op1[0] && op2[0] == 'x')
          return 2;
        if (op2[0] == 's' || op1[0] == '#' || !op2[0])
          return 3;
        size = 3;
        offset = strtol (op1, &endnum, 0) & 0xffff;
        if (endnum && *endnum)
          size++;
        else if (offset > 0xff)
          size++;
        return size;
      default:
        return 4;
    }
}


static asmLineNode *
m6502_asmLineNodeFromLineNode (lineNode *ln)
{
  asmLineNode *aln = newAsmLineNode();
  char *op, op1[256], op2[256];
  int opsize;
  const char *p;
  char inst[8];

  p = ln->line;

  while (*p && isspace(*p)) p++;
  for (op = inst, opsize=1; *p; p++)
    {
      if (isspace(*p) || *p == ';' || *p == ':' || *p == '=')
        break;
      else
        if (opsize < sizeof(inst))
          *op++ = tolower(*p), opsize++;
    }
  *op = '\0';

  if (*p == ';' || *p == ':' || *p == '=')
    return aln;

  while (*p && isspace(*p)) p++;
  if (*p == '=')
    return aln;

  for (op = op1, opsize=1; *p && *p != ','; p++)
    {
      if (!isspace(*p) && opsize < sizeof(op1))
        *op++ = tolower(*p), opsize++;
    }
  *op = '\0';

  if (*p == ',') p++;
  for (op = op2, opsize=1; *p && *p != ','; p++)
    {
      if (!isspace(*p) && opsize < sizeof(op2))
        *op++ = tolower(*p), opsize++;
    }
  *op = '\0';

  aln->size = m6502_instructionSize(inst, op1, op2);

  return aln;
}

static int
m6502_getInstructionSize (lineNode *line)
{
  if (!line->aln)
    line->aln = (asmLineNodeBase *) m6502_asmLineNodeFromLineNode (line);

  return line->aln->size;
}

/** $1 is always the basename.
    $2 is always the output file.
    $3 varies
    $l is the list of extra options that should be there somewhere...
    MUST be terminated with a NULL.
*/
static const char *_linkCmd[] =
{
  "sdld6808", "-nf", "$1", NULL
};

/* $3 is replaced by assembler.debug_opts resp. port->assembler.plain_opts */
static const char *_asmCmd[] =
{
  "sdas6500", "$l", "$3", "$2", "$1.asm", NULL
};

static const char * const _libs_m6502[] = { "m6502", NULL, };
static const char * const _libs_m65c02[] = { "m65c02", NULL, };

/* Globals */
PORT m6502_port =
{
  TARGET_ID_M6502,
  "m6502",
  "MOS 6502",                       /* Target name */
  NULL,                         /* Processor name */
  {
    glue,
    FALSE,                      /* Emit glue around main */
    MODEL_SMALL | MODEL_LARGE,
    MODEL_LARGE,
    NULL,                       /* model == target */
  },
  {
    _asmCmd,
    NULL,
    "-plosgffwy",               /* Options with debug */
    "-plosgffw",                /* Options without debug */
    0,
    ".asm",
    NULL                        /* no do_assemble function */
  },
  {                             /* Linker */
    _linkCmd,
    NULL,
    NULL,
    ".rel",
    1,
    NULL,                       /* crt */
    _libs_m6502,                 /* libs */
  },
  {                             /* Peephole optimizer */
    _m6502_defaultRules,
    m6502_getInstructionSize,
  },
  // TODO: banked func ptr?
  {
    /* Sizes: char, short, int, long, long long, near ptr, far ptr, gptr, func ptr, banked func ptr, bit, float */
    1, 2, 2, 4, 8, 2, 2, 2, 2, 0, 1, 4
  },
  /* tags for generic pointers */
  { 0x00, 0x00, 0x00, 0x00 },           /* far, near, xstack, code */
  {
    "XSEG",
    "STACK",
    "CSEG    (CODE)",
    "DSEG    (PAG)",
    NULL, /* "ISEG" */
    NULL, /* "PSEG" */
    "XSEG",
    NULL, /* "BSEG" */
    "RSEG    (ABS)",
    "GSINIT  (CODE)",
    "OSEG    (PAG, OVR)",
    "GSFINAL (CODE)",
    "HOME    (CODE)",
    "XISEG",              // initialized xdata
    "XINIT   (CODE)",     // a code copy of xiseg
    "CONST   (CODE)",     // const_name - const data (code or not)
    "CABS    (ABS,CODE)", // cabs_name - const absolute data (code or not)
    "XABS    (ABS)",      // xabs_name - absolute xdata
    "IABS    (ABS)",      // iabs_name - absolute data
    NULL,                 // name of segment for initialized variables
    NULL,                 // name of segment for copies of initialized variables in code space
    NULL,
    NULL,
    1,
    1                     // No fancy alignments supported.
  },
  { _m6502_genExtraAreas,
    NULL },
  {
    -1,         /* direction (-1 = stack grows down) */
    0,          /* bank_overhead (switch between register banks) */
    4,          /* isr_overhead */
    2,          /* call_overhead */
    0,          /* reent_overhead */
    0,          /* banked_overhead (switch between code banks) */
    1           /* sp is offset by 1 from last item pushed */
  },
  {
    5, FALSE // TODO: 5 max shift?
  },
  {
    m6502_emitDebuggerSymbol,
    {
      m6502_dwarfRegNum,
      NULL,
      NULL,
      4,                        /* addressSize */
      14,                       /* regNumRet */
      15,                       /* regNumSP */
      -1,                       /* regNumBP */
      1,                        /* offsetSP */
    },
  },
  {
    256,        /* maxCount */
    2,          /* sizeofElement */
    {8,16,32},  /* sizeofMatchJump[] */
    {8,16,32},  /* sizeofRangeCompare[] */
    5,          /* sizeofSubtract */
    10,         /* sizeofDispatch */
  },
  "_",
  _m6502_init,
  _m6502_parseOptions,
  _m6502_options,
  NULL,
  _m6502_finaliseOptions,
  _m6502_setDefaultOptions,
  m6502_assignRegisters,
  _m6502_getRegName,
  0,
  NULL,
  _m6502_keywords,
  _m6502_genAssemblerPreamble,
  _m6502_genAssemblerEnd,        /* no genAssemblerEnd */
  _m6502_genIVT,
  _m6502_genXINIT,
  NULL,                         /* genInitStartup */
  _m6502_reset_regparm,
  _m6502_regparm,
  NULL,                         /* process_pragma */
  NULL,                         /* getMangledFunctionName */
  _hasNativeMulFor,             /* hasNativeMulFor */
  hasExtBitOp,                  /* hasExtBitOp */
  oclsExpense,                  /* oclsExpense */
  TRUE,                         /* use_dw_for_init */
  TRUE,                         /* little_endian */
  0,                            /* leave lt */
  0,                            /* leave gt */
  1,                            /* transform <= to ! > */
  1,                            /* transform >= to ! < */
  1,                            /* transform != to !(a == b) */
  0,                            /* leave == */
  FALSE,                        /* No array initializer support. */
  cseCostEstimation,
  NULL,                         /* no builtin functions */
  GPOINTER,                     /* treat unqualified pointers as "generic" pointers */
  1,                            /* reset labelKey to 1 */
  1,                            /* globals & local statics allowed */
  3,                            /* Number of registers handled in the tree-decomposition-based register allocator in SDCCralloc.hpp */
  PORT_MAGIC
};

PORT m65c02_port =
{
  TARGET_ID_M65C02,
  "m65c02",
  "WDC 65C02",                        /* Target name */
  NULL,                         /* Processor name */
  {
    glue,
    FALSE,                      /* Emit glue around main */
    MODEL_SMALL | MODEL_LARGE,
    MODEL_LARGE,
    NULL,                       /* model == target */
  },
  {
    _asmCmd,
    NULL,
    "-plosgffwy",               /* Options with debug */
    "-plosgffw",                /* Options without debug */
    0,
    ".asm",
    NULL                        /* no do_assemble function */
  },
  {                             /* Linker */
    _linkCmd,
    NULL,
    NULL,
    ".rel",
    1,
    NULL,                       /* crt */
    _libs_m65c02,                  /* libs */
  },
  {                             /* Peephole optimizer */
    _m65c02_defaultRules,
    m6502_getInstructionSize,
  },
  {
    /* Sizes: char, short, int, long, long long, near ptr, far ptr, gptr, func ptr, banked func ptr, bit, float */
    1, 2, 2, 4, 8, 2, 2, 2, 2, 0, 1, 4
  },
  /* tags for generic pointers */
  { 0x00, 0x00, 0x00, 0x00 },           /* far, near, xstack, code */
  {
    "XSEG",
    "STACK",
    "CSEG    (CODE)",
    "DSEG    (PAG)",
    NULL, /* "ISEG" */
    NULL, /* "PSEG" */
    "XSEG",
    NULL, /* "BSEG" */
    "RSEG    (ABS)",
    "GSINIT  (CODE)",
    "OSEG    (PAG, OVR)",
    "GSFINAL (CODE)",
    "HOME    (CODE)",
    "XISEG",              // initialized xdata
    "XINIT   (CODE)",     // a code copy of xiseg
    "CONST   (CODE)",     // const_name - const data (code or not)
    "CABS    (ABS,CODE)", // cabs_name - const absolute data (code or not)
    "XABS    (ABS)",      // xabs_name - absolute xdata
    "IABS    (ABS)",      // iabs_name - absolute data
    NULL,                 // name of segment for initialized variables
    NULL,                 // name of segment for copies of initialized variables in code space
    NULL,
    NULL,
    1,
    1                     // No fancy alignments supported.
  },
  { _m6502_genExtraAreas,
    NULL },
  {
    -1,         /* direction (-1 = stack grows down) */
    0,          /* bank_overhead (switch between register banks) */
    4,          /* isr_overhead */
    2,          /* call_overhead */
    0,          /* reent_overhead */
    0,          /* banked_overhead (switch between code banks) */
    1           /* sp is offset by 1 from last item pushed */
  },
  {
    5, FALSE
  },
  {
    m6502_emitDebuggerSymbol,
    {
      m6502_dwarfRegNum,
      NULL,
      NULL,
      4,                        /* addressSize */
      14,                       /* regNumRet */
      15,                       /* regNumSP */
      -1,                       /* regNumBP */
      1,                        /* offsetSP */
    },
  },
  {
    256,        /* maxCount */
    2,          /* sizeofElement */
    {8,16,32},  /* sizeofMatchJump[] */
    {8,16,32},  /* sizeofRangeCompare[] */
    5,          /* sizeofSubtract */
    10,         /* sizeofDispatch */
  },
  "_",
  _m65c02_init,
  _m6502_parseOptions,
  _m6502_options,
  NULL,
  _m6502_finaliseOptions,
  _m6502_setDefaultOptions,
  m6502_assignRegisters,
  _m6502_getRegName,
  0,
  NULL,
  _m6502_keywords,
  _m6502_genAssemblerPreamble,
  _m6502_genAssemblerEnd,        /* no genAssemblerEnd */
  _m6502_genIVT,
  _m6502_genXINIT,
  NULL,                         /* genInitStartup */
  _m6502_reset_regparm,
  _m6502_regparm,
  NULL,                         /* process_pragma */
  NULL,                         /* getMangledFunctionName */
  _hasNativeMulFor,             /* hasNativeMulFor */
  hasExtBitOp,                  /* hasExtBitOp */
  oclsExpense,                  /* oclsExpense */
  TRUE,                         /* use_dw_for_init */
  TRUE,                         /* little_endian */
  0,                            /* leave lt */
  0,                            /* leave gt */
  1,                            /* transform <= to ! > */
  1,                            /* transform >= to ! < */
  1,                            /* transform != to !(a == b) */
  0,                            /* leave == */
  FALSE,                        /* No array initializer support. */
  cseCostEstimation,
  NULL,                         /* no builtin functions */
  GPOINTER,                     /* treat unqualified pointers as "generic" pointers */
  1,                            /* reset labelKey to 1 */
  1,                            /* globals & local statics allowed */
  3,                            /* Number of registers handled in the tree-decomposition-based register allocator in SDCCralloc.hpp */
  PORT_MAGIC
};

