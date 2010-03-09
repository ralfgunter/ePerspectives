%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_gs).
-behaviour(gen_server).

-include("persp.hrl").

%% gen_server exports
-export([init/1, terminate/2, code_change/3]).
-export([handle_call/3, handle_cast/2, handle_info/2]).

%% gen_server initialization
init([]) ->
	crypto:start(),		% There must be a better way to do this
	Servers = [],
	ParsedResults = [],
	BinaryResults = [],
	Results = {BinaryResults, ParsedResults},
	{ok, {Servers, Results}}.


%% Call handling
handle_call({add_server, IP, Port, Public_Key}, _From, {Servers, Results}) ->
	{Response, NewServers} = persp:add_server(IP, Port, Public_Key, Servers),
	{reply, Response, {NewServers, Results}};

handle_call({del_server, IP}, _From, {Servers, Results}) ->
	{Response, NewServers} = persp:add_server(IP, Servers),
	{reply, Response, {NewServers, Results}};

handle_call({scan_service_id, Service_ID}, _From, {Servers, Results}) ->
	{ok, Socket} = gen_udp:open(?DEFAULT_PORT, ?UDP_OPTIONS),
	{ok, NewBinaryResults} = persp:scan_service_id(Service_ID, Servers, Socket),
	ok = gen_udp:close(Socket),
	
	{_BinaryResults, ParsedResults} = Results,
	
	{reply, ok, {Servers, {NewBinaryResults, ParsedResults}}};

handle_call(print, _From, {Servers, {BinaryResults, _ParsedResults}}) ->
	{ok, ParsedList} = persp_parser:parse_messages(BinaryResults),
	persp:pretty_print(ParsedList),
	
	{reply, ok, {Servers, {BinaryResults, ParsedList}}}.


%% Required gen_server 'definitions'
handle_cast(_Message, State) -> {noreply, State}.
handle_info(_Message, State) -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_OldVersion, State, _Extra) -> {ok, State}.
