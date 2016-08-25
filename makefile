# Adapted from https://web.stanford.edu/class/cs107/guide_make.html

###########################################################################
## Build Flags & Library Dependencies
###########################################################################

CC = g++
CFLAGS = -g -Wall
# CFLAGS += -Dmemcmp=timingsafe_memcmp
LDFLAGS = -lssl -lcrypto -lboost_unit_test_framework -lboost_chrono -lboost_system -lzmq
INCLUDE = -I ./include

# The CFLAGS variable sets compile flags for gcc:
#  -g        compile with debug information
#  -Wall     give verbose compiler warnings

# Add path to libressl if OSX or Ubuntu-(if compiled from source)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
		LDFLAGS += -L/usr/local/opt/libressl/lib
		INCLUDE += -I/usr/local/opt/libressl/include
endif

ifeq ($(UNAME_S),Linux)
		LDFLAGS += -L/usr/local/lib
endif

.PHONY: clean BIN_DIR

###########################################################################
## Global Variables
###########################################################################

BIN = bin/
SOURCE = src/
LIB = ./bin/
TEST = ./src/test/
CRYPTO = $(SOURCE)crypto/
UTILITY = $(SOURCE)utility/

all: BIN_DIR  bob_client tumbler_server signer_server

# Create Bin Directory
BIN_DIR:
	test  -d bin || mkdir bin

###########################################################################
## UTILITY
###########################################################################

UTILITY_SOURCES = /utility.cpp /bin.cpp /network.cpp /timer.cpp /memory.cpp
UTILITY_OBJECTS = $(subst /,$(BIN),$(UTILITY_SOURCES:.cpp=.o))
UTILITY_TEST_TARGETS = utility_test bin_test
DEPEND = $(UTILITY_OBJECTS)

# Compile Objects
$(UTILITY_OBJECTS):
	$(CC) $(CFLAGS) -c $(subst $(BIN),$(UTILITY), $(@:.o=.cpp)) -o $@ $(INCLUDE)


# Compile Targets
$(UTILITY_TEST_TARGETS) : $(DEPEND)
	$(CC) $(CFLAGS) -o $(BIN)$@ $(TEST)$@.cpp $^ $(INCLUDE) $(LDFLAGS)

###########################################################################
## Crypto
###########################################################################

CRYPTO_SOURCES = /blind_rsa.cpp /ec.cpp /encrypt.cpp /hash.cpp /random.cpp
CRYPTO_OBJECTS = $(subst /,$(BIN),$(CRYPTO_SOURCES:.cpp=.o))
CRYPTO_TEST_TARGETS = blind_rsa_test ec_test encrypt_test hash_test
DEPEND += $(CRYPTO_OBJECTS)

# Compile Objects
$(CRYPTO_OBJECTS):
	$(CC) $(CFLAGS) -c $(subst $(BIN),$(CRYPTO), $(@:.o=.cpp)) -o $@ $(INCLUDE)


# Compile Targets
$(CRYPTO_TEST_TARGETS) : $(DEPEND)
	$(CC) $(CFLAGS) -o $(BIN)$@ $(TEST)$@.cpp $^ $(INCLUDE) $(LDFLAGS)

###########################################################################
## Protocol Dependencies
###########################################################################

SCC_SOURCES = /scc.cpp /tx.cpp
SCC_OBJECTS = $(subst /,$(BIN),$(SCC_SOURCES:.cpp=.o))
SCC_TEST_TARGETS = scc_test
DEPEND += $(SCC_OBJECTS)

# Compile Objects
$(SCC_OBJECTS):
	$(CC) $(CFLAGS) -c $(subst $(BIN),$(SOURCE), $(@:.o=.cpp)) -o $@ $(INCLUDE)


# Compile Targets
$(SCC_TEST_TARGETS) : $(DEPEND)
	$(CC) $(CFLAGS) -o $(BIN)$@ $(TEST)$@.cpp $^ $(INCLUDE) $(LDFLAGS)

###########################################################################
## Client -- Alice & Bob (same machine)
###########################################################################

CLIENT_SOURCES = /alice.cpp /alice_client.cpp /bob.cpp
CLIENT_OBJECTS = $(subst /,$(BIN),$(CLIENT_SOURCES:.cpp=.o))
CLIENT_TARGETS = bob_client alice_client_test

# Compile Objects
$(CLIENT_OBJECTS):
	$(CC) $(CFLAGS) -c $(subst $(BIN),$(SOURCE), $(@:.o=.cpp)) -o $@ $(INCLUDE)


# Compile Targets
$(CLIENT_TARGETS) : $(DEPEND) $(CLIENT_OBJECTS)
	$(CC) $(CFLAGS) -o $(BIN)$@ $(SOURCE)$@.cpp $^ $(INCLUDE) $(LDFLAGS)

###########################################################################
## Server -- The Tumbler System
###########################################################################

SERVER_SOURCES = /tumbler.cpp /signer.cpp
SERVER_OBJECTS = $(subst /,$(BIN),$(SERVER_SOURCES:.cpp=.o))
SERVER_TARGETS = tumbler_server signer_server

# Compile Objects
$(SERVER_OBJECTS):
	$(CC) $(CFLAGS) -c $(subst $(BIN),$(SOURCE), $(@:.o=.cpp)) -o $@ $(INCLUDE)


# Compile Targets
$(SERVER_TARGETS) :$(DEPEND) $(SERVER_OBJECTS)
	$(CC) $(CFLAGS) -o $(BIN)$@ $(SOURCE)$@.cpp $^ $(INCLUDE) $(LDFLAGS)

###########################################################################
## Other Targets
###########################################################################

clean:
	rm -rf $(BIN)*
