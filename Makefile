.PHONY: asn client server

all: asn client server

asn:
	@$(MAKE) -C common
	@cp common/RSA.beam client/ebin/
	@cp common/RSA.beam server/ebin/
	@cp common/RSA.hrl client/src/
	@cp common/RSA.hrl server/src/

client:
	@$(MAKE) -C client
	@cp client/ebin/persp_crypto.beam server/ebin/

server:
	@$(MAKE) -C server
