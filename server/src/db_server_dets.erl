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
start_link(Sid_table_file, Fingerprint_table_file) ->
	gen_server:start_link({local, db_serv}, ?MODULE, 
							[Sid_table_file, Fingerprint_table_file], []).

init([Sid_file, Fingerprint_file]) ->
	load_db_files([Sid_file, Fingerprint_file]),
	process_flag(trap_exit, true),
	{ok, {}}.

terminate(_Reason, _State) ->
	dets:close(sids),
	dets:close(fingerprints).

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

handle_cast({update_entry, Fingerprint, NewTimestamp}, Files) ->
	update_entry(Fingerprint, NewTimestamp),
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
	dets:insert(sids, {Service_ID, Fingerprint}),
	dets:insert(fingerprints, {Fingerprint, [{Timestamp, Timestamp}]}).

update_entry(Fingerprint, NewEnd) ->
	[[Timestamps]] = dets:match(fingerprints, {Fingerprint, '$1'}),
	[{Beg, _OldEnd} | Rest] = Timestamps,
	
	dets:update_element(fingerprints, Fingerprint, {2, [{Beg, NewEnd} | Rest]}).

check_cache(Service_ID) ->
	case dets:member(sids, Service_ID) of
		true ->
			Fingerprints_list = check_service_id(Service_ID),
			Timestamps_list   = check_fingerprints(Fingerprints_list),
			ResultPairs = lists:zip(Fingerprints_list, Timestamps_list),
			
			ResultPairs;
		false ->
			[]
	end.

list_all_sids() ->
	dets:match(sids, {'$1', _ = '_'}).

%% Query processing
check_service_id(Service_ID) ->
	TempList = dets:match(sids, {Service_ID, '$1'}),
	Result  = lists:append(TempList),
	
	Result.

check_fingerprints(Fingerprints_list) ->
	check_fingerprints(Fingerprints_list, []).

check_fingerprints([], Results) ->
	Results;

check_fingerprints([CurrentFingerprint | Rest], ResultsSoFar) ->
	[[Timestamps]] = dets:match(fingerprints, {CurrentFingerprint, '$1'}),
	check_fingerprints(Rest, [Timestamps | ResultsSoFar]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Database initialization and loading
load_db_files([Sid_filename, Fingerprint_filename]) ->
	dets:open_file(sids, [{type, bag}, {file, Sid_filename}]),
	dets:open_file(fingerprints, [{file, Fingerprint_filename}]).
