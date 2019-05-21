LIBSEAL_PATH = /usr/local/lib/libseal.a

OPTFLAGS = -O3 -fomit-frame-pointer -fno-strict-aliasing
DBGFLAGS = -O0 -ggdb3
CXXFLAGS += $(DBGFLAGS) -Wall -Wextra -pedantic -std=gnu++17 -fPIC -DPIC -fopenmp -pthread
#CPPFLAGS = -Ipath/to/seal.h
LDFLAGS = -fopenmp -pthread

LIB_OBJS = seclink.o encrypt.o decrypt.o multiply.o
LIB = libseclink.so
EXE_OBJS = secure-linkage.o
EXE = secure-linkage

all: $(EXE)

clean:
	$(RM) $(LIB_OBJS) $(LIB) $(EXE_OBJS) $(EXE)

$(LIB): $(LIB_OBJS)
	$(CXX) -shared -o $(LIB) $(LIB_OBJS) $(LDFLAGS) $(LIBSEAL_PATH)

# TODO: all the libseal stuff should be accessed via libseclink.so, so
# remove $LIBSEAL_PATH from this command
$(EXE): $(LIB) $(EXE_OBJS)
	$(CXX) -o $(EXE) $(EXE_OBJS) -Wl,-rpath=. $(LIB) $(LDFLAGS) $(LIBSEAL_PATH)

keygen: $(LIB) keygen.o
	$(CXX) -o keygen keygen.o -Wl,-rpath=. $(LIB) $(LDFLAGS) $(LIBSEAL_PATH)
