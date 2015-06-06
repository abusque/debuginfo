CC=gcc
CFLAGS=-c -Wall -g
LDFLAGS=-lelf -lm -ldwarf
SOURCES=main.c so_info.c durin.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=debuginfo

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(OBJECTS) $(EXECUTABLE)
