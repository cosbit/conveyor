CC ?= cc
CLANG ?= clang
CFLAGS ?= -O2 -g
PREFIX ?= /usr/local
BPF_OBJECT ?= $(abspath build/bridge.bpf.o)
IP_COMMAND ?= ip

all: build/conveyor
build:
	mkdir -p $@
build/bridge.bpf.o: src/bridge.bpf.c src/bridge.h | build
	$(CLANG) -target bpf -O2 -g -Wall -Werror $(BPF_CPPFLAGS) -I src -c $< -o $@
build/conveyor: src/conveyor.c src/bridge.h build/bridge.bpf.o
	$(CC) $(CFLAGS) -Wall -Wextra -Werror -DBPF_OBJECT='"$(BPF_OBJECT)"' -DIP_COMMAND='"$(IP_COMMAND)"' $< -o $@ $$(pkg-config --cflags --libs libbpf)
install: all
	install -Dm755 build/conveyor $(DESTDIR)$(PREFIX)/bin/conveyor
	install -Dm644 build/bridge.bpf.o $(DESTDIR)$(PREFIX)/lib/conveyor/bridge.bpf.o
clean:
	rm -rf build
.PHONY: all install clean
