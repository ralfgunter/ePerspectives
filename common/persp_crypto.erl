%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_crypto).

-include("RSA.hrl").

-export([verify_rsa_signature/3]).
-export([pem_key_to_der/1, decode_der/1, public_exp/1, modulus/1]).
-export([key_fingerprint/1]).

verify_rsa_signature(Data, Signature, Public_Key) ->
    DERBinary = pem_key_to_der(Public_Key),
    WrappedKey = decode_der(DERBinary),
    
    Public_Exponent = public_exp(WrappedKey),
    Modulus         = modulus(WrappedKey),
    
    Mpint_exp = crypto:mpint(Public_Exponent),
    Mpint_mod = crypto:mpint(Modulus),
    
    Mpint_data = <<(byte_size(Data)):32/integer-big, Data/binary>>,
    Mpint_sign = <<(byte_size(Signature)):32/integer-big, Signature/binary>>,
    
    crypto:rsa_verify(md5, Mpint_data, Mpint_sign, [Mpint_exp, Mpint_mod]).


% Do not confuse this with public_key:pem_to_der; this takes as argument
% a string with the key already in it, instead of a File.
pem_key_to_der(Key) ->
    Lines = string:tokens(Key, "\n"),
    MiddleLines = lists:sublist(Lines, 2, (length(Lines) - 2)),
    FinalString = string:join(MiddleLines, "\n"),
    
    base64:decode(FinalString).


decode_der(DERBinary) ->
    {ok, WrappedBin} = 'RSA':decode('WrappedKey', DERBinary),
    {_Unused, KeyBin} = WrappedBin#'WrappedKey'.publicKey,
    {ok, DecodedKey} = 'RSA':decode('RSAPublicKey', KeyBin),
    
    DecodedKey.

public_exp(WrappedKey) ->
    WrappedKey#'RSAPublicKey'.publicExponent.

modulus(WrappedKey) ->
    WrappedKey#'RSAPublicKey'.modulus.

key_fingerprint(SSHKey) ->
    % WARNING: undocumented erlang function: this might break in the future!
    EncodedKey = ssh_file:encode_public_key(SSHKey),
    
    crypto:md5(EncodedKey).
