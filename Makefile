CC=gcc
CFLAGS=-c -Wall -g $(shell pkg-config --cflags glib-2.0)
LDFLAGS=-lelf -lm -ldwarf $(shell pkg-config --libs glib-2.0)
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
