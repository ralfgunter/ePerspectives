SERVER_SRC = $(wildcard src/*.erl)
SERVER_OBJ = $(SERVER_SRC:src/%.erl=ebin/%.beam)

all: server
server: ${SERVER_OBJ}

ebin/%.beam: src/%.erl
	erlc -o `dirname $@` $<

clean:
	rm -rf ebin/*
