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
% TODO: Check math: header + max_domain + ":" + max_port + "," + type
-define(MAX_LENGTH, 273).

%% External API
-export([start_link/2]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

-record(scan_data, {socket, address, port, data}).
-record(state, {socket, module}).

%%--------------------------------------------------------------------
%% @spec (Port::integer(), Module) -> {ok, Pid} | {error, Reason}
%
%% @doc Called by a supervisor to start the listening process.
%% @end
%%----------------------------------------------------------------------
start_link(Port, Module) when is_integer(Port), is_atom(Module) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, {Port, Module}, []).

%%%------------------------------------------------------------------------
%%% Callback functions from gen_server
%%%------------------------------------------------------------------------

init({Port, Module}) ->
    case gen_udp:open(Port, ?UDP_OPTIONS) of
        {ok, Socket} ->
            process_flag(trap_exit, true),
            proc_lib:init_ack({ok, self()}),
            loop(Socket, Module);
        {error, Reason} ->
            {stop, Reason}
    end.

loop(Socket, Module) ->
    case gen_udp:recv(Socket, ?MAX_LENGTH) of
        {ok, {Address, Port, Data}} ->
            ScanData = #scan_data{socket = Socket, address = Address,
                                  port = Port, data = Data},
            persp_scanner_sup:dispatch_scanner(ScanData),
            loop(Socket, Module);
        {error, Reason} ->
            error_logger:error_msg("Error receiving data: ~p\n", [Reason]),
            loop(Socket, Module)
    end.

% TODO: this will never be executed - fix it
terminate(_Reason, State) ->
    gen_udp:close(State#state.socket),
    ok.

code_change(_OldVersion, State, _Extra) ->
    {ok, State}.

handle_call(Request, _From, State) ->
    {stop, {unknown_call, Request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.
