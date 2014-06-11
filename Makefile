# Compiler
CC=g++

# Compiler flag
CFLAGS=-g3 -O0 -c -Wall -D_POSIX_THREADS_ -std=c++0x
# Linker flag
LDFLAGS= -lcrypto -lssl -lpthread

SOURCES=main.cpp CService.cpp CServer.cpp CSslConnection.cpp CSubscribers.cpp CLog.cpp CDateTime.cpp CProducts.cpp CDb.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=Server

all: $(SOURCES) $(EXECUTABLE)

# link all object
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile for object
.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *o Server

