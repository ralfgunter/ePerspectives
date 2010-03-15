%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(db_server_ets).
-behaviour(gen_server).

%% External API
-export([start_link/2, init_db_files/2]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

%% Records
-record(db_files, {sid_file, fingerprint_file}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_server callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(Sid_table_file, Fingerprint_table_file) ->
	gen_server:start_link({local, ?MODULE}, ?MODULE, 
							[Sid_table_file, Fingerprint_table_file], []).

init([Sid_file, Fingerprint_file]) ->
	case load_db_files([Sid_file, Fingerprint_file]) of
		ok ->
			process_flag(trap_exit, true),
			Files = #db_files{sid_file = Sid_file,
								fingerprint_file = Fingerprint_file},
			{ok, Files};
		{error, Reason} ->
			error_logger:error_msg("Could not load database: ~p\n", [Reason]),
			{stop, Reason}
	end.

terminate(_Reason, Files) ->
	ets:tab2file(sid_table,         Files#db_files.sid_file),
	ets:tab2file(fingerprint_table, Files#db_files.fingerprint_file).

code_change(_OldVersion, Files, _Extra) ->
	{ok, Files}.

handle_cast(_Msg, Files) ->
    {noreply, Files}.

handle_info(_Info, Files) ->
    {noreply, Files}.


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
	ets:insert(sid_table, {Service_ID, Fingerprint}),
	ets:insert(fingerprint_table, {Fingerprint, Timestamp, Timestamp}).

check_cache(Service_ID) ->
	case ets:member(sid_table, Service_ID) of
		true ->
			Fingerprints_list = check_service_id(Service_ID),
			Timestamps_list   = check_fingerprints(Fingerprints_list),
			ResultPairs = lists:zip(Fingerprints_list, Timestamps_list),
			
			ResultPairs;
		false ->
			[]
	end.

%% Query processing
check_service_id(Service_ID) ->
	TempList = ets:match(sid_table, {Service_ID, '$1'}),
	Result = lists:flatten(TempList),
	
	Result.

check_fingerprints(Fingerprints_list) ->
	check_fingerprints(Fingerprints_list, []).

check_fingerprints([], Results) ->
	Results;

check_fingerprints([CurrentFingerprint | Rest], ResultsSoFar) ->
	Timestamps = ets:match(fingerprint_table, {CurrentFingerprint, '$1', '$2'}),
	check_fingerprints(Rest, [Timestamps | ResultsSoFar]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Database initialization and loading
init_db_files(Sid_filename, Fingerprint_filename) ->
	ets:new(sid_table, [bag, named_table]),
	ets:new(fingerprint_table, [bag, named_table]),
	
	ets:tab2file(sid_table, Sid_filename),
	ets:tab2file(fingerprint_table, Fingerprint_filename).

% This function attempts to populate the database with the supplied FileList.
% Should it fail for any of the files, it immediately exits the 'loop'.
load_db_files(FileList) ->
	load_db_files(FileList, ok).

load_db_files(_FileList, {error, Reason}) ->
	{error, Reason};

load_db_files([], ok) ->
	ok;

load_db_files([Filename | Rest], ok) ->
	case ets:file2tab(Filename) of
		{ok, _Table} ->
			load_db_files(Rest, ok);
		{error, Reason} ->
			load_db_files([], {error, Reason})
	end.
