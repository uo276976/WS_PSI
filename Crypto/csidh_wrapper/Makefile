CC = gcc
CFLAGS = -O3 -Wall -fPIC
LDFLAGS = -shared -Wl,--version-script=exports.txt

INCLUDES = -I./faster-csidh

SRC = libcsidh.c \
      faster-csidh/csidh.c \
      faster-csidh/mont.c \
      faster-csidh/rng.c \
      faster-csidh/u512.s \
      faster-csidh/fp.s

OBJ = $(SRC:.c=.o)
OBJ := $(OBJ:.s=.o)

OUT = libcsidh.so

all: $(OUT)

$(OUT): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ 

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

%.o: %.s
	@echo "Assembling $<"
	cat $< > tmp_$(notdir $*).s
	echo ".section .note.GNU-stack,\"\",@progbits" >> tmp_$(notdir $*).s
	$(CC) -x assembler -fPIC -c tmp_$(notdir $*).s -o $@
	rm tmp_$(notdir $*).s

clean:
	rm -f $(OBJ) $(OUT)
