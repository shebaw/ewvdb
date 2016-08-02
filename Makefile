#Set this variable to point to your SDK directory
IDA=../../

#Set this variable to the desired name of your compiled loader
PROC=ewvdb_loader

ifndef __LINUX__
PLATFORM_CFLAGS=-D__NT__ -D__IDP__ -mno-cygwin
PLATFORM_LDFLAGS=--dll -mno-cygwin
IDALIB=$(IDA)lib/x86_win_gcc_32/ida.a
LOADER_EXT=.ldw
else
PLATFORM_CFLAGS=-D__LINUX__
IDALIB=$(IDA)lib/x86_linux_gcc_32/pro.a
LOADER_EXT=.llx
endif

#Platform specific compiler flags
CFLAGS=-Wextra $(PLATFORM_CFLAGS)

#Platform specific ld flags
LDFLAGS=-Wl -shared -s $(PLATFORM_LDFLAGS) 

#specify any additional libraries that you may need
EXTRALIBS=

# Destination directory for compiled plugins
OUTDIR=$(IDA)bin/loaders/

#list out the object files in your project here
OBJS=ewvdb_loader.o

BINARY=$(OUTDIR)$(PROC)$(LOADER_EXT)

all: $(OUTDIR) $(BINARY)

clean:
	-@rm *.o
	-@rm $(BINARY)

$(OUTDIR):
	-@mkdir -p $(OUTDIR)

CC=i586-mingw32msvc-g++
INC=-I$(IDA)include/

%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

LD=i586-mingw32msvc-g++


$(BINARY): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(IDALIB) $(EXTRALIBS) 

#change pcap_loader below to the name of your loader, make sure to add any 
#additional files that your loader is dependent on
ewvdb_loader.o: ewvdb_loader.cpp
