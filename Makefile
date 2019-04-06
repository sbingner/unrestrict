TARGET  = Unrestrict.dylib
OUTDIR ?= bin
DSYMDIR ?= dsym
PREFIX ?= /Library/MobileSubstrate/ServerPlugins
ARCHS  ?= arm64
SRC	= $(wildcard *.c helpers/*.c offset-cache/*.c)
OBJ	= $(SRC:.c=.o)

CC      = xcrun -sdk iphoneos gcc $(patsubst %,-arch %,$(ARCHS))
LDID    = ldid
CFLAGS  = -I. -Ihelpers -Ioffset-cache -Wno-deprecated-declarations -g
LDFLAGS = -framework IOKit -framework CoreFoundation

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG
endif

.PHONY: all install clean

all: $(OUTDIR)/$(TARGET)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $^

install: all
	install -d "$(DESTDIR)$(PREFIX)"
	install $(OUTDIR)/$(TARGET) "$(DESTDIR)$(PREFIX)"

$(OUTDIR):
	mkdir -p $@

$(DSYMDIR):
	mkdir -p $@

$(OUTDIR)/$(TARGET): $(OBJ) | $(OUTDIR) $(DSYMDIR)
	$(CC) $(LDFLAGS) -dynamiclib -install_name $(PREFIX)/$(TARGET) -o $@ $^
	dsymutil $@ -out $(DSYMDIR)/$(TARGET).dSYM
	strip -S $@
	$(LDID) -S $@

install: all

clean:
	rm -rf $(OUTDIR) $(OBJ)
