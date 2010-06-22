%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_udp_listener).
-behaviour(gen_server).

%% External API
-export([start_link/1]).
-export([send_results/2]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

-define(UDP_OPTIONS, [binary, {reuseaddr, true}, {active, true}]).

-record(client_info, {socket, address, port, data}).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(Port) when is_integer(Port) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Port, []).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_server callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init(Port) ->
    case gen_udp:open(Port, ?UDP_OPTIONS) of
        {ok, Socket} ->
            {ok, Socket};
        {error, Reason} ->
            {stop, Reason}
    end.

terminate(_Reason, Socket) ->
    gen_udp:close(Socket).

code_change(_OldVersion, Socket, _Extra) -> {ok, Socket}.
handle_call(Request, _From, Socket) -> {stop, {unknown_call, Request}, Socket}.
handle_cast(_Msg, Socket) -> {noreply, Socket}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% "Connection" handlers
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
handle_info({udp, _Socket, ClientAddress, Port, Data}, Socket) ->
    ClientInfo = #client_info{socket = Socket, address = ClientAddress,
                              port   = Port,   data    = Data},
    persp_scanner_sup:handle_request(udp, ClientInfo),
    
    {noreply, Socket};

handle_info(_Info, Socket) -> {noreply, Socket}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
send_results(ClientInfo, Results) ->
    ClientAddress = ClientInfo#client_info.address,
    ClientSocket  = ClientInfo#client_info.socket,
    ClientPort    = ClientInfo#client_info.port,
    
    case gen_udp:send(ClientSocket, ClientAddress, ClientPort, Results) of
        ok ->
            ok;
        {error, Reason} ->
            error_logger:error_msg("Failed to send results: ~p\n", [Reason])
    end.
