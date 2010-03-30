%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_scanner_sup).
-behaviour(supervisor).

%% External API
-export([get_scanner/0]).
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
get_scanner() ->
	case ets:match(scanners, {spawningmode, '$1'}) of
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
start_link(ScannerModule, basic) ->
	ets:new(scanners, [named_table, public]),
	ets:insert(scanners, {spawningmode, basic}),
	
	supervisor:start_link({local, ?MODULE}, ?MODULE, [ScannerModule]).

start_link(ScannerModule, prefork, ScannersNumLowerBound) ->
	ets:new(scanners, [named_table, public]),
	ets:insert(scanners, {spawningmode, prefork}),
	ets:insert(scanners, {lowerbound, ScannersNumLowerBound}),
	
	Result = supervisor:start_link({local, ?MODULE}, ?MODULE, [ScannerModule]),
	prefork_add(ScannersNumLowerBound),
	Result.

init([ScannerModule]) ->
    {ok,
        {_SupFlags = {simple_one_for_one, ?MAX_RESTART, ?MAX_TIME},
            [
              % Scanner
              {   scanner,
                  {ScannerModule, start_link, []},
                  temporary,
                  2000,
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
%% Basic - scanners are spawned only on-demand
basic_spawn() ->
	supervisor:start_child(?MODULE, []).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Prefork - starts with a number of scanners, spawning more if necessary

% Adds new scanners to the scanners list.
prefork_add(0) ->
	ok;

prefork_add(Counter) ->
	{ok, Pid} = supervisor:start_child(?MODULE, []),
	ets:insert(scanners, {Pid, waiting}),
	prefork_add(Counter - 1).

% Looks for an available (waiting) scanner child in the scanners list.
% If one is found, it is returned, and its entry is properly updated.
% Otherwise, it spawns a new one (but doesn't add it to the list).
prefork_spawn() ->
	case ets:match(scanners, {'$1', waiting}) of
		[] ->
			supervisor:start_child(?MODULE, []);
		Matches ->
			[Pid] = lists:nth(1, Matches),
			ets:update_element(scanners, Pid, {2, scanning}),
			{ok, Pid}
	end.

% Deletes a terminated scanner from the scanners list.
child_terminated(Pid) ->
	case ets:match(scanners, {spawningmode, '$1'}) of
		[[prefork]] ->
			% If the terminated child was in the list, spawn another one to
			% replace it; this guarantees that the number of scanners remains at
			% least ScannersNumLowerBound.
			% Otherwise, it was spawned to keep up with the demand, and thus
			% does not need to be replaced.
			case ets:member(scanners, Pid) of
				true ->
					ets:delete(scanners, Pid),
					prefork_add(1);
				false ->
					ok
			end;
		[[basic]] ->
			ok
	end.
