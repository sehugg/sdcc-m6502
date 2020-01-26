/*
this test fails on -mz80 with --oldralloc
*/

#include <testfwk.h>
#include <string.h>

typedef unsigned char byte;
typedef signed char sbyte;
typedef unsigned short word;

word dvgram[0x1000];

//

int dvgwrofs; // write offset for DVG buffer

inline void dvgreset() {
  dvgwrofs = 0;
}

void dvgwrite(word w) {
  dvgram[dvgwrofs++] = w;
}

void VCTR(int dx, int dy, byte bright) {
  dvgwrite((dy & 0x1fff));
  dvgwrite(((bright & 7) << 13) | (dx & 0x1fff));
}

inline void CNTR() {
  dvgwrite(0x8000);
}

inline void HALT() {
  dvgwrite(0x2000);
}

///

typedef struct {
  sbyte m[3][3];
} Matrix;

typedef struct {
  sbyte x,y,z;
} Vector8;

typedef struct {
  int x,y,z;
} Vector16;

typedef struct {
  byte numverts;
  const Vector8* verts; // array of vertices
  const sbyte* edges; // array of vertex indices (edges)
} Wireframe;

const Matrix IDENTITY = {{{127,0,0},{0,127,0},{0,0,127}}};

void mat_identity(Matrix* m) {
  memset(m, 0, sizeof(*m));
  m->m[0][0] = 127;
  m->m[1][1] = 127;
  m->m[2][2] = 127;
}

void vec_mat_transform(Vector16* dest, const Vector8* v, const Matrix* m) {
  dest->x = v->x*m->m[0][0] + v->y*m->m[0][1] + v->z*m->m[0][2];
  dest->y = v->x*m->m[1][0] + v->y*m->m[1][1] + v->z*m->m[1][2];
  dest->z = v->x*m->m[2][0] + v->y*m->m[2][1] + v->z*m->m[2][2];
}

const Vector8 tetra_v[] = { {0,-86,86},{86,86,86},{-86,86,86},{0,0,-86} };
const char tetra_e[] = { 0, 1, 2, 0, 3, 1, -1, 3, 2, -2 };
const Wireframe tetra = { 4, tetra_v, tetra_e };

void xform_vertices(Vector16* dest, const Vector8* src, const Matrix* m, byte nv) {
  byte i;
  for (i=0; i<nv; i++) {
    vec_mat_transform(dest++, src++, m);
  }
}

void draw_wireframe_ortho(const Wireframe* wf, const Matrix* m) {
  Vector16 scrnverts[16];
  const char* e = wf->edges;
  byte bright = 0;
  int x1 = 0;
  int y1 = 0;
  xform_vertices(scrnverts, wf->verts, m, wf->numverts);
  do {
    sbyte i = *e++;
    if (i == -1)
      bright = 0;
    else if (i == -2)
      break;
    else {
      int x2 = scrnverts[i].x>>8;
      int y2 = scrnverts[i].y>>8;
      VCTR(x2-x1, y2-y1, bright);
      x1 = x2;
      y1 = y2;
    }
    bright = 2;
  } while (1);
}

///

void testBug (void) {
  Matrix m;
  mat_identity(&m);
  dvgreset();
  CNTR();
  draw_wireframe_ortho(&tetra, &m);
  HALT();
  ASSERT (dvgram[0] == 0x8000);
  ASSERT (dvgram[1] == 0x1fd5);
  ASSERT (dvgram[2] == 0x0000);
  ASSERT (dvgram[3] == 0x0055);
  ASSERT (dvgram[4] == 0x402a);
  ASSERT (dvgram[5] == 0x0000);
  ASSERT (dvgram[6] == 0x5fab);
  ASSERT (dvgram[7] == 0x1fab);
  ASSERT (dvgram[15] == 0x002a);
}
