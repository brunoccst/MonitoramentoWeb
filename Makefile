OBJS = Sniffer.o
CC = g++
DEBUG = -g
CFLAGS = -Wall -c $(DEBUG)
LFLAGS = -Wall $(DEBUG)

make : $(OBJS)
	$(CC) -Wall $(OBJS) -o Sniffer 

clean:
	\rm *.o Sniffer 

