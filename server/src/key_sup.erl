%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(key_sup).
-behaviour(supervisor).

-include_lib("public_key/include/public_key.hrl").

%% External API
-export([get_signer/0]).
-export([prefork_add/1]).

%% Supervisor behaviour callbacks
-export([start_link/2, start_link/3]).
-export([init/1]).

%% Spawners and related functions
-export([basic_spawn/0, prefork_spawn/0]).
-export([child_terminated/1]).

-define(MAX_RESTART,     5).
-define(MAX_TIME,       60).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
get_signer() ->
    case ets:match(signers, {spawningmode, '$1'}) of
		[[basic]] ->
			basic_spawn();
		[[prefork]] ->
			prefork_spawn()
	end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Supervisor behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(PrivateKeyFilepath, basic) ->
    ets:new(signers, [named_table, public]),
    ets:insert(signers, {spawningmode, basic}),
    
	PrivKey = process_key_file(PrivateKeyFilepath),
	
    supervisor:start_link({local, ?MODULE}, ?MODULE, PrivKey).

start_link(PrivateKeyFilepath, prefork, ScannersNumLowerBound) ->
	ets:new(signers, [named_table, public]),
	ets:insert(signers, {spawningmode, prefork}),
	ets:insert(signers, {lowerbound, ScannersNumLowerBound}),
	
	PrivKey = process_key_file(PrivateKeyFilepath),
	
	Result = supervisor:start_link({local, ?MODULE}, ?MODULE, PrivKey),
	prefork_add(ScannersNumLowerBound),
	Result.

init(PrivKey) ->
	{ok,
		{_SupFlags = {simple_one_for_one, ?MAX_RESTART, ?MAX_TIME},
			[
				% Signer
				{	signer,
					{key_signer, start_link, [PrivKey]},
					temporary,
					brutal_kill,
					worker,
					[]
				}
			]
		}
	}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Spawning modes
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Basic - children are spawned only on-demand
basic_spawn() ->
	supervisor:start_child(?MODULE, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Prefork - starts with a number of children, spawning more if necessary

% Adds new signers to the signers list.
prefork_add(0) ->
	ok;

prefork_add(Counter) ->
	{ok, Pid} = supervisor:start_child(?MODULE, []),
	ets:insert(signers, {Pid, waiting}),
	prefork_add(Counter - 1).

% Looks for an available (waiting) signer child in the signers list.
% If one is found, it is returned, and its entry is properly updated.
% Otherwise, it spawns a new one (but doesn't add it to the list).
prefork_spawn() ->
	case ets:match(signers, {'$1', waiting}) of
		[] ->
			supervisor:start_child(?MODULE, []);
		Matches ->
			[Pid] = lists:nth(1, Matches),
			ets:update_element(signers, Pid, {2, scanning}),
			{ok, Pid}
	end.

% Deletes a terminated signer from the signers list.
child_terminated(Pid) ->
	case ets:match(signers, {spawningmode, '$1'}) of
		[[prefork]] ->
			% If the terminated child was in the list, spawn another one to
			% replace it; this guarantees that the number of signers remains at
			% least ScannersNumLowerBound.
			% Otherwise, it was spawned to keep up with the demand, and thus
			% does not need to be replaced.
			case ets:member(signers, Pid) of
				true ->
					ets:delete(signers, Pid),
					prefork_add(1);
				false ->
					ok
			end;
		[[basic]] ->
			ok
	end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
process_key_file(PrivKeyFilepath) ->
	%% Private key parsing.
	% TODO: do something about password-protected private keys
	{ok, [KeyInfo]}  = public_key:pem_to_der(PrivKeyFilepath),
	{ok, PrivateKey} = public_key:decode_private_key(KeyInfo),
	
	PrivateKey.
