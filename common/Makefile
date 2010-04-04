all: compiler_tool rsa

compiler_tool: compile_asn1.erl
	erlc compile_asn1.erl

rsa:
	erl -pa ./ -run compile_asn1 compile -run init stop -noshell

clean:
	rm *.beam RSA.asn1db RSA.erl RSA.hrl
