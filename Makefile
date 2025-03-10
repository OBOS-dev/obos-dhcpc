LD := $(CC)
CC_FLAGS := -fno-strict-aliasing -g -O0
LD_FLAGS := -lpcap
all: build obos_dhcpd

bin/main.o: src/main.c
	$(CC) -c $(CC_FLAGS) $< -o $@
bin/interface.o: src/interface.c
	$(CC) -c $(CC_FLAGS) $< -o $@
bin/dhcp.o: src/dhcp.c
	$(CC) -c $(CC_FLAGS) $< -o $@

obos_dhcpd: bin/main.o bin/interface.o bin/dhcp.o
	$(LD) -oobos_dhcpc $^ $(LD_FLAGS)

clean:
	@rm -rf bin/
build:
	@mkdir -p bin/
.PHONY: build clean
