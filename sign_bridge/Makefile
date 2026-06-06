.PHONY: all clean

all:
	gcc -shared -fPIC -O2 -o libsign_bridge.so sign_bridge.c -ldl -lpthread -Wl,--export-dynamic

clean:
	rm -f libsign_bridge.so
