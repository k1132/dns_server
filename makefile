FLAGS		= -Wall -g -lpthread -pthread -D_REENTRANT
CC			= gcc
PROG		= dnsserver
OBJS		= objs/dnsserver.o

all:	objcrt ${PROG} #clear

objcrt:
	if [ ! -d objs ]; then mkdir ./objs; fi
	if [ ! -d pipes ]; then mkdir ./pipes; fi

clean:
	rm -rf objs/ pipes/ ${OBJS} ${PROG}

clear:
	clear

${PROG}: ${OBJS}
	${CC} ${OBJS} ${FLAGS} -o $@

##########################

#each program's dependencies:
${PROG}: ${OBJS}

##########################

#########################

#PRG SPECIFIC OBJS:
objs/%.o : %.c
	$(CC) $< $(FLAGS) -c -o $@

clean:
	-rm -f ${OBJS}