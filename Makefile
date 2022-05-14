obj = chatroom.o wrap.o utils.o

all : ${obj} 
	cc -o chatroom ${obj}

chatroom.o : data_type.h wrap.h utils.h 
wrap.o : wrap.h
utils.o : utils.h

clean :
	-rm ${obj} a.out chatroom
