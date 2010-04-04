.PHONY: client

CLIENT_SRC = $(wildcard src/*.erl)
CLIENT_OBJ = $(CLIENT_SRC:src/%.erl=ebin/%.beam)

all: client
client: ${CLIENT_OBJ}

ebin/%.beam: src/%.erl
	erlc -o `dirname $@` $<

clean:
	rm -rf ebin/*.beam
