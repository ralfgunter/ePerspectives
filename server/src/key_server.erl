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
start_link(PublicKeyFilepath, PrivateKeyFilepath) ->
	gen_server:start_link({local, ?MODULE}, ?MODULE,
							{PublicKeyFilepath, PrivateKeyFilepath}, []).

init({PubKeyFilepath, PrivKeyFilepath}) ->
	{PrivKey, PubKey} = process_key_files(PrivKeyFilepath, PubKeyFilepath),
	
	{ok, PrivKey, PubKey}.

terminate(_Reason, State) ->
	ok.

code_change(_OldVersion, State, _Extra) ->
	{ok, State}.

handle_call(Request, _From, State) ->
    {stop, {unknown_call, Request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
process_key_files(PrivKeyFilepath, PubKeyFilepath) ->
	%% Private key parsing
	{ok, Entry} = public_key:pem_to_der(PrivKeyFilepath)
