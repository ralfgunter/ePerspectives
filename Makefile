.PHONY: common client server

all: common client server

common:
	@$(MAKE) -C common
	@cp common/RSA.beam client/ebin/
	@cp common/RSA.beam server/ebin/
	@cp common/persp_crypto.beam client/ebin/
	@cp common/persp_crypto.beam server/ebin/

client:
	@$(MAKE) -C client

server:
	@$(MAKE) -C server

clean:
	@$(MAKE) -C common clean
	@$(MAKE) -C client clean
	@$(MAKE) -C server clean
