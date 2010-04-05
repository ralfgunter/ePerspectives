all: compiler_tool rsa crypto

compiler_tool: compile_asn1.erl
	erlc compile_asn1.erl

rsa:
	erl -pa ./ -run compile_asn1 compile -run init stop -noshell

crypto: persp_crypto.erl
	erlc persp_crypto.erl

clean:
	rm *.beam RSA.asn1db RSA.erl RSA.hrl
