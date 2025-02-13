LD := $(CC)
all: build obos_dhcpd

bin/main.o: src/main.c
	$(CC) -c $(CC_FLAGS) src/main.c -o bin/main.o
bin/eth.o: src/eth.c
	$(CC) -c $(CC_FLAGS) src/eth.c -o bin/eth.o

obos_dhcpd: bin/main.o bin/eth.o
	$(LD) -oobos_dhcpd $(LD_FLAGS) $^

clean:
	@rm -rf bin/
build:
	@mkdir -p bin/
.PHONY: build clean
