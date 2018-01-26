OUT = go
CC = gcc
ODIR = obj
SDIR = .
IDIR = .
INC = mylibc/libmylibc.a sha256_asm/libsha256x8664.a
CFLAGS = -Isecp256k1_fast_unsafe/src -Isha256_asm -O2
MAKE = make

_DEPS = 
_OBJ = 
LIBS = -lm -lsha256_x8664 -lmylibc -lgmp -lart


DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(OUT): ListPrivateKey.c
	$(CC) $(INC) -o $@ $^ $(CFLAGS) $(LIBS)

$(DEPS):
.PHONY: clean

clean:
	rm -f $(ODIR)/*.o $(OUT)
	
all:
	