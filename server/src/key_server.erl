-module(key_server).
-behaviour(gen_server).

-include_lib("public_key/include/public_key.hrl").

%% External API
-export([start_link/2]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% persp_scanner callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(PrivateKeyFilepath, PublicKeyFilepath) ->
	gen_server:start_link({local, ?MODULE}, ?MODULE,
							{PrivateKeyFilepath, PublicKeyFilepath}, []).

init({PrivKeyFilepath, PubKeyFilepath}) ->
	{PrivKey, PubKey} = process_key_files(PrivKeyFilepath, PubKeyFilepath),
	
	{ok, {PrivKey, PubKey}}.

terminate(_Reason, _State) ->
	ok.

code_change(_OldVersion, State, _Extra) ->
	{ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Call handling
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
handle_call({sign, Data}, _From, {PrivKey, PubKey}) ->
	% TODO: make DigestType customizable
	Private_Exponent = PrivKey#'RSAPrivateKey'.privateExponent,
	Public_Exponent  = PrivKey#'RSAPrivateKey'.publicExponent,
	Modulus          = PrivKey#'RSAPrivateKey'.modulus,
	
	Mp_priv_exp = crypto:mpint(Private_Exponent),
	Mp_pub_exp  = crypto:mpint(Public_Exponent),
	Mp_mod      = crypto:mpint(Modulus),
	
	Mp_data = << (byte_size(Data)):32/integer-big, Data/binary >>,
	
	Signature = crypto:rsa_sign(md5, Mp_data, [Mp_pub_exp, Mp_mod, Mp_priv_exp]),
	
	{reply, Signature, {PrivKey, PubKey}};

handle_call(Request, _From, State) ->
    {stop, {unknown_call, Request}, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
process_key_files(PrivKeyFilepath, PubKeyFilepath) ->
	%% Private key parsing.
	% TODO: do something about password-protected private keys
	{ok, [KeyInfo]}  = public_key:pem_to_der(PrivKeyFilepath),
	{ok, PrivateKey} = public_key:decode_private_key(KeyInfo),
	
	%% Public key parsing.
	{ok, KeyBin} = file:read_file(PubKeyFilepath),
	DERBinary = persp_crypto:pem_key_to_der(binary_to_list(KeyBin)),
	PublicKey = persp_crypto:decode_der(DERBinary),
	
	{PrivateKey, PublicKey}.
