srcs    := $(wildcard *.c)
headers := $(wildcard *.h)
objs    := $(patsubst %.c,%.o,$(srcs))
exec    := ibdev2netdev

CC := gcc
CCFLAGS := -O2 -Wall -Wextra -Werror -Wmissing-prototypes -Wmissing-declarations -Wwrite-strings -Wformat=2 -Wformat-nonliteral -Wdate-time -Wnested-externs -Wshadow -Wstrict-prototypes -Wold-style-definition -Wredundant-decls $(CFLAGS)
LDFLAGS := -libverbs

all: $(exec)

$(exec): $(objs) Makefile
	$(CC) $(CCFLAGS) -o $@ $(objs) $(LDFLAGS)

%.o:%.c Makefile $(headers)
	$(CC) $(CCFLAGS) -o $@ -c $<

clean:
	rm -f $(objs) $(exec)
