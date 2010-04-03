%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(key_signer).
-behaviour(gen_fsm).

-include_lib("public_key/include/public_key.hrl").

%% Events
-export([start_to_sign/3]).

%% gen_fsm callbacks
-export([start_link/1]).
-export([init/1, terminate/3]).
-export([handle_event/3, handle_info/3, handle_sync_event/4]).
-export([code_change/4]).

%% FSM states
-export(['SIGN'/2]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Events
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_to_sign(Pid, Data, ScannerPid) ->
	gen_fsm:send_event(Pid, {sign, Data, ScannerPid}).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_fsm callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(PrivKey) ->
	gen_fsm:start_link(?MODULE, PrivKey, []).

init(PrivKey) ->
	{ok, 'SIGN', PrivKey}.

handle_info(_Info, StateName, StateData) ->
	{noreply, StateName, StateData}.

handle_sync_event(Event, _From, StateName, StateData) ->
	{stop, {StateName, undefined_event, Event}, StateData}.

handle_event(Event, StateName, StateData) ->
	{stop, {StateName, undefined_event, Event}, StateData}.

terminate(_Reason, _StateName, _State) ->
	% TODO: Do away with this.
	% There should be no need for a signer to explicitly (in contrast to the
	% regular erlang methods) inform the supervisor that it has terminated.
	% This is probably inefficient in a large scale and ties the implementation
	% of the child with the supervisor's.
	key_sup:child_terminated(self()),
	ok.

code_change(_OldVsn, StateName, StateData, _Extra) ->
	{ok, StateName, StateData}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% FSM States
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
'SIGN'({sign, Data, ScannerPid}, PrivKey) ->
	{ok, SignedData} = sign(Data, PrivKey),
	ScannerPid ! {ok, SignedData},
	
	{stop, normal, PrivKey}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
sign(Data, PrivKey) ->
	% TODO: make DigestType customizable
	Private_Exponent = PrivKey#'RSAPrivateKey'.privateExponent,
	Public_Exponent  = PrivKey#'RSAPrivateKey'.publicExponent,
	Modulus          = PrivKey#'RSAPrivateKey'.modulus,
	
	Mp_priv_exp = crypto:mpint(Private_Exponent),
	Mp_pub_exp  = crypto:mpint(Public_Exponent),
	Mp_mod      = crypto:mpint(Modulus),
	
	Mp_data = << (byte_size(Data)):32/integer-big, Data/binary >>,
	
	Signature = crypto:rsa_sign(md5, Mp_data, [Mp_pub_exp, Mp_mod, Mp_priv_exp]),
	
	{ok, Signature}.
