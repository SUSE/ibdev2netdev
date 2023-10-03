srcs    := $(wildcard *.c)
headers := $(wildcard *.h)
objs    := $(patsubst %.c,%.o,$(srcs))
exec    := ibdev2netdev

CC := gcc
CCFLAGS := -O2 -Wall -Wextra $(CFLAGS)
LDFLAGS := -libverbs

all: $(exec)

$(exec): $(objs) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(objs)

%.o:%.c Makefile $(headers)
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(objs) $(exec)
