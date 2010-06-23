SERVER_SRC = $(wildcard src/*.erl)
SERVER_OBJ = $(SERVER_SRC:src/%.erl=ebin/%.beam)

all: server
server: ${SERVER_OBJ}

ebin/%.beam: src/%.erl
	erlc -pa ebin/ -o ebin/ $<

clean:
	rm -rf ebin/*.beam
