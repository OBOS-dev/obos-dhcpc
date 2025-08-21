CC := x86_64-obos-gcc
LD := $(CC)
CC_FLAGS := -fno-strict-aliasing -g -O0
LD_FLAGS :=
all: build obos_dhcpd
prefix := /usr/local

bin/main.obos.o: src/main.obos.c
	$(CC) -c $(CC_FLAGS) $< -o $@
bin/interface.o: src/interface.c
	$(CC) -c $(CC_FLAGS) $< -o $@
bin/dhcp.o: src/dhcp.c
	$(CC) -c $(CC_FLAGS) $< -o $@
bin/x86_64-syscall-obos.o: src/x86_64-syscall-obos.S
	$(CC) -c $(CC_FLAGS) $< -o $@

obos_dhcpd: bin/main.obos.o bin/interface.o bin/dhcp.o bin/x86_64-syscall-obos.o
	$(LD) -oobos_dhcpd $^ $(LD_FLAGS)

install: obos_dhcpd
	install -d $(prefix)
	install -d $(prefix)/sbin
	install -m 755 obos_dhcpd $(prefix)/sbin
uninstall:
	rm $(prefix)/sbin/obos_dhcpd

clean:
	@rm -rf bin/
build:
	@mkdir -p bin/
.PHONY: build clean install uninstall all
