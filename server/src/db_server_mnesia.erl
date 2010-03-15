%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(db_server_mnesia).
-behaviour(gen_server).

%% External API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

-record(scan_cache, {service_id, fingerprint, timestamp_beg, timestamp_end}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% persp_scanner callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link() ->
	gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
	case mnesia:start() of
		ok ->
			process_flag(trap_exit, true),
			create_tables(),
			{ok, node()};
		{error, Reason} ->
			{stop, Reason}
	end.

terminate(_Reason, _State) ->
	mnesia:stop(),
	ok.

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
handle_call({check_cache, Service_ID}, _From, State) ->
	CacheList = check_cache(Service_ID),
	{reply, CacheList, State};

handle_call({add_entry, Service_ID, Fingerprint, Timestamp}, _From, State) ->
	add_entry(Service_ID, Fingerprint, Timestamp),
	{reply, ok, State};

handle_call(Request, _From, State) ->
    {stop, {unknown_call, Request}, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
create_tables() ->
	mnesia:create_table(scan_cache, [{type, bag},
						{attributes, record_info(fields, scan_cache)}]).

check_cache(Service_ID) ->
	F = fun() ->
		mnesia:read(scan_cache, Service_ID)
	end,
	{atomic, CacheList} = mnesia:transaction(F),
	
	CacheList.

add_entry(Service_ID, Fingerprint, Timestamp) ->
	F = fun() ->
		Entry = #scan_cache{service_id = Service_ID, fingerprint = Fingerprint,
							timestamp_beg = Timestamp,
							timestamp_end = Timestamp},
		mnesia:write(Entry)
	end,
	{atomic, _} = mnesia:transaction(F).
