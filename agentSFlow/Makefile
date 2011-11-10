HEADERS = sflow_api.h sflow.h Makefile

#INCLUDEDIRS = -I. -I/opt/libpcap/include
INCLUDEDIRS = -I. -I/usr/include/pcap

# OPT = -O2 -mcpu=i686 -march=i686 -fno-strength-reduce
OPT = -g -ggdb

LDOPT =

CFLAGS = -D_GNU_SOURCE -DSTDC_HEADERS $(INCLUDEDIRS) $(OPT) -W
# CFLAGS = -D_GNU_SOURCE -DSTDC_HEADERS $(INCLUDEDIRS) $(OPT) -W -DSFL_USE_32BIT_INDEX

#CC = gcc
CC = g++

PCAPLIB = /usr/local/lib/libpcap.a
#PCAPLIB = -lpcap

OBJS = sflow_agent.o sflow_sampler.o sflow_poller.o sflow_receiver.o sflsp.o

PROGRAM = sflsp

all: $(PROGRAM)

sflsp: $(OBJS) $(PCAPLIB)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(PCAPLIB)

.C.o: $(HEADERS)
	$(CC) $(CFLAGS) -c $*.C

clean:
	rm -f *.o $(PROGRAM)

# dependencies
sflow_agent.o: sflow_agent.C $(HEADERS)
sflow_sampler.o: sflow_sampler.C $(HEADERS)
sflow_poller.o: sflow_poller.C $(HEADERS)
sflow_receiver.o: sflow_receiver.C $(HEADERS)
sflsp.o: sflsp.C $(HEADERS)
