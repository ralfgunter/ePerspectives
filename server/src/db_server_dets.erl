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
	gen_server:start_link({local, ?MODULE}, ?MODULE, 
							[Sid_table_file, Fingerprint_table_file], []).

init([Sid_file, Fingerprint_file]) ->
	load_db_files([Sid_file, Fingerprint_file]),
	process_flag(trap_exit, true),
	{ok, {}}.

terminate(_Reason, _State) ->
	dets:close(sid_table),
	dets:close(fingerprint_table).

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
handle_call({check_cache, Service_ID}, _From, Files) ->
	Cache = check_cache(Service_ID),
	{reply, Cache, Files};

handle_call({add_entry, Service_ID, Fingerprint, Timestamp}, _From, Files) ->
	add_entry(Service_ID, Fingerprint, Timestamp),
	{reply, ok, Files};

handle_call({update_entry, Fingerprint, NewTimestamp}, _From, Files) ->
	update_entry(Fingerprint, NewTimestamp),
	{reply, ok, Files};

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
	dets:insert(sid_table, {Service_ID, Fingerprint}),
	dets:insert(fingerprint_table, {Fingerprint, Timestamp, Timestamp}).

update_entry(Fingerprint, NewTimestampEnd) ->
	List = dets:match(fingerprint_table, {Fingerprint, '$1', '$2'}),
	[Beg, OldEnd] = lists:last(List),
	
	dets:delete_object(fingerprint_table, {Fingerprint, Beg, OldEnd}),
	dets:insert(fingerprint_table, {Fingerprint, Beg, NewTimestampEnd}).

check_cache(Service_ID) ->
	case dets:member(sid_table, Service_ID) of
		true ->
			Fingerprints_list = check_service_id(Service_ID),
			Timestamps_list   = check_fingerprints(Fingerprints_list),
			ResultPairs = lists:zip(Fingerprints_list, Timestamps_list),
			
			ResultPairs;
		false ->
			[]
	end.

list_all_sids() ->
	dets:match(sid_table, {'$1', _ = '_'}).

%% Query processing
check_service_id(Service_ID) ->
	TempList = dets:match(sid_table, {Service_ID, '$1'}),
	Result  = lists:flatten(TempList),
	
	Result.

check_fingerprints(Fingerprints_list) ->
	check_fingerprints(Fingerprints_list, []).

check_fingerprints([], Results) ->
	Results;

check_fingerprints([CurrentFingerprint | Rest], ResultsSoFar) ->
	Timestamps = dets:match(fingerprint_table,{CurrentFingerprint, '$1', '$2'}),
	check_fingerprints(Rest, [Timestamps | ResultsSoFar]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Database initialization and loading
load_db_files([Sid_filename, Fingerprint_filename]) ->
	dets:open_file(sid_table, [{type, bag}, {file, Sid_filename}]),
	dets:open_file(fingerprint_table,[{type, bag},{file,Fingerprint_filename}]).
