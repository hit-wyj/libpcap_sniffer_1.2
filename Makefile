BIN = lsniffer
CC  = gcc
INC  = -I. -I./kernel/ -I./base/
CFLAGS  = -g -Wall -lpcap
OBJECTS = $(wildcard ./*.c ./kernel/*.c ./base/*.c)

$(BIN): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(INC)
clean:
	rm -fr ./*.o lsniffer
