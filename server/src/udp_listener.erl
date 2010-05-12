%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(udp_listener).
-behaviour(gen_server).

-define(UDP_OPTIONS, [binary, {reuseaddr, true}, {active, false}]).
-define(MAX_LENGTH, 273).

%% External API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

-record(scan_data, {socket, address, port, data}).

%%--------------------------------------------------------------------
%% @spec (Port::integer(), Module) -> {ok, Pid} | {error, Reason}
%
%% @doc Called by a supervisor to start the listening process.
%% @end
%%----------------------------------------------------------------------
start_link(Port) when is_integer(Port) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Port, []).

%%%------------------------------------------------------------------------
%%% Callback functions from gen_server
%%%------------------------------------------------------------------------

init(Port) ->
    case gen_udp:open(Port, ?UDP_OPTIONS) of
        {ok, Socket} ->
            process_flag(trap_exit, true),
            proc_lib:init_ack({ok, self()}),
            loop(Socket);
        {error, Reason} ->
            {stop, Reason}
    end.

loop(Socket) ->
    case gen_udp:recv(Socket, ?MAX_LENGTH) of
        {ok, {Address, Port, Data}} ->
            ScanData = #scan_data{socket = Socket, address = Address,
                                  port = Port, data = Data},
            persp_scanner_sup:handle_request({udp, ScanData}),
            loop(Socket);
        {error, Reason} ->
            error_logger:error_msg("Error receiving data: ~p\n", [Reason]),
            loop(Socket)
    end.

% TODO: this will never be executed - fix it
terminate(_Reason, Socket) ->
    gen_udp:close(Socket),
    ok.

code_change(_OldVersion, Socket, _Extra) ->
    {ok, Socket}.

handle_call(Request, _From, Socket) ->
    {stop, {unknown_call, Request}, Socket}.

handle_cast(_Msg, Socket) ->
    {noreply, Socket}.

handle_info(_Info, Socket) ->
    {noreply, Socket}.
