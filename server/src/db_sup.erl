%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(db_sup).
-behaviour(supervisor).

%% External API
-export([get_db/0]).

%% Supervisor behaviour callbacks
-export([start_link/3, start_link/4]).
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
get_db() ->
    case ets:match(db, {spawningmode, '$1'}) of
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
start_link(DBModule, {Sid_file, Fingerprint_file}, basic) ->
	ets:new(db, [named_table, public]),
	ets:insert(db, {spawningmode, basic}),
	
	DBModule:load_db_files([Sid_file, Fingerprint_file]),
	
	supervisor:start_link({local, db_sup}, ?MODULE, DBModule).

start_link(DBModule, {Sid_file, Fingerprint_file}, prefork, MinChildren) ->
	ets:new(db, [named_table, public]),
	ets:insert(db, {spawningmode, prefork}),
	ets:insert(db, {lowerbound, MinChildren}),
	
	DBModule:load_db_files([Sid_file, Fingerprint_file]),
	
	Result = supervisor:start_link({local, db_sup}, ?MODULE, DBModule),
	prefork_add(MinChildren),
	Result.

init(DBModule) ->
	{ok,
		{_SupFlags = {simple_one_for_one, ?MAX_RESTART, ?MAX_TIME},
			[
				% Database
				{	database,
					{DBModule, start_link, []},
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

% Adds new db to the db list.
prefork_add(0) ->
	ok;

prefork_add(Counter) ->
	{ok, Pid} = supervisor:start_child(?MODULE, []),
	ets:insert(db, {Pid, waiting}),
	prefork_add(Counter - 1).

% Looks for an available (waiting) signer child in the db list.
% If one is found, it is returned, and its entry is properly updated.
% Otherwise, it spawns a new one (but doesn't add it to the list).
prefork_spawn() ->
	case ets:match(db, {'$1', waiting}) of
		[] ->
			supervisor:start_child(?MODULE, []);
		Matches ->
			Min = ets:lookup_element(db, lowerbound, 2),
			[Pid] = lists:nth(random:uniform(Min), Matches),
			{ok, Pid}
	end.

% Deletes a terminated signer from the db list.
child_terminated(Pid) ->
	case ets:match(db, {spawningmode, '$1'}) of
		[[prefork]] ->
			% If the terminated child was in the list, spawn another one to
			% replace it; this guarantees that the number of db remains at
			% least ScannersNumLowerBound.
			% Otherwise, it was spawned to keep up with the demand, and thus
			% does not need to be replaced.
			case ets:member(db, Pid) of
				true ->
					ets:delete(db, Pid),
					prefork_add(1);
				false ->
					ok
			end;
		[[basic]] ->
			ok
	end.

