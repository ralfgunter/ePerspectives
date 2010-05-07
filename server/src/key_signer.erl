%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(key_signer).
-behaviour(gen_server).

-include_lib("public_key/include/public_key.hrl").

%% External API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(KeyTuple) ->
	gen_server:start_link(?MODULE, KeyTuple, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_server callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init(KeyTuple) ->
	{ok, KeyTuple}.

terminate(_Reason, _KeyTuple) ->
	% TODO: Do away with this.
	% There should be no need for a signer to explicitly (in contrast to the
	% regular erlang methods) inform the supervisor that it has terminated.
	% This is probably inefficient in a large scale and ties the implementation
	% of the child with the supervisor's.
	key_sup:child_terminated(self()),
	ok.

code_change(_OldVersion, KeyTuple, _Extra) ->
	{ok, KeyTuple}.

handle_cast(_Msg, KeyTuple) ->
    {noreply, KeyTuple}.

handle_info(_Info, KeyTuple) ->
    {noreply, KeyTuple}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Call handling
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
handle_call({sign, Data}, _From, KeyTuple) ->
	{ok, Signature} = sign(Data, KeyTuple),
	
	{reply, Signature, KeyTuple}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
sign(Data, {Mp_priv_exp, Mp_pub_exp, Mp_mod}) ->
	% TODO: make DigestType customizable
	Mp_data = << (byte_size(Data)):32/integer-big, Data/binary >>,
	Signature = crypto:rsa_sign(md5, Mp_data, [Mp_pub_exp, Mp_mod, Mp_priv_exp]),
	
	{ok, Signature}.
