LDLIBS=-lpcap

all: tcp-block

tcp-block: main.o header/scheme/ip.o header/scheme/mac.o header/ethhdr.o header/iphdr.o header/tcphdr.o kmp.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET) *.o