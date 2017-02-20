CC=clang
CFLAGS=-fobjc-arc -fobjc-link-runtime -framework Foundation src/libcapstone.a

build/ioskextdump:
	mkdir -p build;
	$(CC) $(CFLAGS) src/*.m -o $@

.PHONY:install
install:build/ioskextdump
	mkdir -p /usr/local/bin
	cp build/ioskextdump /usr/local/bin/ioskextdump

.PHONY:uninstall
uninstall:
	rm /usr/local/bin/ioskextdump

.PHONY:clean
clean:
	rm -rf build
