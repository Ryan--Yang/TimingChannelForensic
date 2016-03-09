# Project: pcap_mysql
# Makefile created by Rillke Zhou

CPP      = g++
CC       = gcc
CSRC     = pcap_mysql.c
OBJ      = $(CSRC:.c=.o)
LINKOBJ  = $(CSRC:.c=.o)
LIBS     = -L/usr/lib/ -lmysqlclient -I/usr/include/mysql -lpcap
INCS     = 
CXXINCS  = 
BIN      = pcap_mysql
CXXFLAGS = $(CXXINCS) 
CFLAGS   = $(INCS) 
RM       = rm -f
.PHONY: all all-before all-after clean clean-custom

all: all-before $(BIN) all-after

clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LINKOBJ) -o $(BIN) $(LIBS)
# ---------------------------------------------------------------------------
# rules for code generation
# ---------------------------------------------------------------------------
%.o:    %.c
	$(CC) $(CFLAGS) -o $@ $(LIBS) -c $<

%.o:    %.S
	$(CC) $(ASFLAGS) -o $@ -c $<
