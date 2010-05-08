%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(rescan_server).
-behaviour(gen_server).

%% External API
-export([start_link/2]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(Interval_length, ScannerList) ->
	gen_server:start_link({local, ?MODULE}, ?MODULE,
							[Interval_length, ScannerList], []).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_server callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init([Interval_length, ScannerList]) ->
	case prepare_timers(Interval_length, ScannerList) of
		{ok, TimerRefs} ->
			{ok, TimerRefs};
		{error, Reason} ->
			error_logger:error_msg("Failed to setup timers: ~p\n", [Reason]),
			{error, Reason}
	end.

terminate(_Reason, TimerRefs) ->
	delete_timers(TimerRefs),
	ok.

code_change(_OldVersion, TimerRefs, _Extra) ->
	{ok, TimerRefs}.

handle_call(_Msg, _From, TimerRefs) ->
	{noreply, TimerRefs}.

handle_cast(_Msg, TimerRefs) ->
    {noreply, TimerRefs}.

handle_info(_Info, TimerRefs) ->
    {noreply, TimerRefs}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
prepare_timers(Interval, ScannerList) ->
	prepare_timers(Interval, ScannerList, []).

prepare_timers(_Interval, [], TimerRefs) ->
	{ok, TimerRefs};

prepare_timers(Interval, [CurrentScanner | Rest], TimerRefs) ->
	case timer:apply_interval(Interval, CurrentScanner, rescan_all, []) of
		{ok, TRef} ->
			prepare_timers(Interval, Rest, [{CurrentScanner, TRef} | TimerRefs]);
		{error, Reason} ->
			{error, Reason}
	end.

delete_timers(TimerList) ->
	lists:foreach(fun(Ref) -> timer:cancel(Ref) end, TimerList).
