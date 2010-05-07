%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(db_server_dets).
-behaviour(gen_server).

%% External API
-export([start_link/2]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_server callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(Cache_filename, Sids_filename) ->
	gen_server:start_link({local, db_serv}, ?MODULE,
						  [Cache_filename, Sids_filename], []).

init(DBFiles) ->
	load_db_files(DBFiles),
	process_flag(trap_exit, true),
	
	{ok, {}}.

terminate(_Reason, _State) ->
	dets:close(sids),
	dets:close(cache).

code_change(_OldVersion, State, _Extra) ->
	{ok, State}.

handle_info(_Info, State) ->
    {noreply, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Cast handling (asynchronous commands)
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
handle_cast({add_entry, Service_ID, Fingerprint, Timestamp}, Files) ->
	add_entry(Service_ID, Fingerprint, Timestamp),
	{noreply, ok, Files};

handle_cast({update_entry, Service_ID, Fingerprint, NewTimestamp}, Files) ->
	update_entry(Service_ID, Fingerprint, NewTimestamp),
	{noreply, ok, Files};

handle_cast(_Msg, State) ->
    {noreply, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Call handling
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
handle_call({check_cache, Service_ID}, _From, Files) ->
	Cache = check_cache(Service_ID),
	{reply, Cache, Files};

handle_call({list_all_sids}, _From, Files) ->
	List = list_all_sids(),
	{reply, List, Files};

handle_call(Request, _From, Files) ->
    {stop, {unknown_call, Request}, Files}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Queries
add_entry(Service_ID, Fingerprint, Timestamp) ->
	add_fingerprint(Service_ID, Fingerprint),
	
	% TODO: put this in its own function?
	dets:insert(cache, { {Service_ID, Fingerprint},
						 [ {Timestamp, Timestamp} ]
					   }).

update_entry(Service_ID, Fingerprint, NewEnd) ->
	Timestamps = get_timestamps(Service_ID, Fingerprint),
	update_timestamps(Service_ID, Fingerprint, Timestamps, NewEnd).

check_cache(Service_ID) ->
	case dets:member(sids, Service_ID) of
		true ->
			Fingerprints = check_service_id(Service_ID),
			Timestamps   = check_fingerprints(Service_ID, Fingerprints),
			ResultPairs  = lists:zip(Fingerprints, Timestamps),
			
			ResultPairs;
		false ->
			[]
	end.

list_all_sids() ->
	% TODO: find a function that lists all the keys in a table.
	Results = dets:match(sids, {'$1', _ = '_'}),
	
	lists:append(Results).

%% Query processing
check_service_id(Service_ID) ->
	% TODO: find a function that's as lightweight as lookup, but returns only
	% the matching objects' values, instead of the entire object.
	TempList = dets:lookup(sids, Service_ID),
	
	lists:map(fun({_Key, Value}) -> Value end, TempList).

check_fingerprints(Service_ID, Fingerprints) ->
	Lambda = fun(CurrentFingerprint) ->
		get_timestamps(Service_ID, CurrentFingerprint)
	end,
	
	lists:map(Lambda, Fingerprints).

%% Database internal representation
add_fingerprint(Service_ID, Fingerprint) ->
	dets:insert(sids, {Service_ID, Fingerprint}).

get_timestamps(Service_ID, Fingerprint) ->
	[{_Key, Timestamps}] = dets:lookup(cache, {Service_ID, Fingerprint}),
	
	Timestamps.

update_timestamps(Service_ID, Fingerprint, Timestamps, NewEnd) ->
	[{Beg, _OldEnd} | Rest] = Timestamps,
	
	% TODO: put this in its own function?
	dets:insert(cache, { {Service_ID, Fingerprint},
						 [ {Beg, NewEnd} | Rest ]
					   }).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Database initialization and loading
load_db_files([Sids_filename, Cache_filename]) ->
	dets:open_file(sids,  [{file, Sids_filename}, {type, bag}]),
	dets:open_file(cache, [{file, Cache_filename}]).
