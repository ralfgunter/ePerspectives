-module(compile_asn1).
-export([compile/0]).

compile() -> asn1ct:compile("RSA.asn", [ber_bin, optimize, der, compact_bit_string]).
