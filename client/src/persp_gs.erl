%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_gs).
-behaviour(gen_server).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_server callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init([]) ->
    crypto:start(),     % There must be a better way to do this
    Servers = [],
    ParsedResults = [],
    RawResults = [],
    Results = {RawResults, ParsedResults},
    
    {ok, {Servers, Results}}.

handle_cast(_Message, State) ->
    {noreply, State}.

handle_info(_Message, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVersion, State, _Extra) ->
    {ok, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Call handling
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Adding and deleting notary servers
handle_call({add_server, ServerHeader}, _From, {Servers, Results}) ->
    {Response, NewServers} = persp:add_server(ServerHeader, Servers),
    
    {reply, Response, {NewServers, Results}};

handle_call({del_server, Address}, _From, {Servers, Results}) ->
    {Response, NewServers} = persp:add_server(Address, Servers),
    
    {reply, Response, {NewServers, Results}};

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Fetching and printing scan results
handle_call({scan, ScanHeader}, _From, {Servers, Results}) ->
    {ok, NewRawResults} = persp:scan(ScanHeader, Servers),
    {_, ParsedResults}  = Results,
    
    {reply, ok, {Servers, {NewRawResults, ParsedResults}}};

handle_call(print, _From, {Servers, {RawResults, _ParsedResults}}) ->
    % TODO: properly cache the parsed messages
    {ok, ParsedList} = persp_parser:parse_messages(RawResults),
    persp:pretty_print(ParsedList),
    
    {reply, ok, {Servers, {RawResults, ParsedList}}}.
