%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_scanner_sup).
-behaviour(supervisor).

%% External API
-export([handle_request/2, handle_scan_results/4]).
-export([get_ssl_scanner/0]).

%% Supervisor behaviour callbacks
-export([start_link/1]).
-export([init/1]).

-record(client_info, {socket, address, port, data}).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Scan request handling
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Requests that are made via UDP are handled differently from those
%% made via HTTP:
%%
%% UDP:  - The listener merely receives scan requests and dispatches scanners
%%         to handle them; it assumes that the results will be sent by someone
%%         else.
%%       - The reason for this is that the listener CANNOT block on the scan,
%%         since that would delay dispatching other requests.
%%
%% HTTP: - The listener not only receives requests but also sees to it that they
%%         are replied to, thanks to inets' ability to spawn a new process for
%%         each "HTTP request".
%%       - Unlike above, the process spawned by the httpd CAN (and perhaps even
%%         should) block on the scan, since it only affects that single request.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% UDP
handle_request(udp, ClientInfo) ->
    % ServerInfo: {Address, Port, Service_type}
    %           - information about the server
    % ClientInfo: {ClientSocket, ClientAddress, ClientPort, ClientData}
    %           - information about the client (plus the scan request it sent)
    ServerInfo = persp_udp_parser:parse_clientinfo(ClientInfo),
    {ServerAddress, ServerPort, Service_type} = ServerInfo,
    
    % TODO: put these somewhere else
    OkFun = fun(Service_ID, Results) ->
        BinResults = persp_udp_parser:prepare_response(Service_ID, Results),
        persp_udp_listener:send_results(ClientInfo, BinResults)
    end,
    ErrorFun = fun(Reason) ->
        error_logger:error_msg("Error handling request from ~p:~p of
                                ~p:~p ~p\n~p\n",
                                [ClientInfo#client_info.address,
                                 ClientInfo#client_info.port,
                                 ServerAddress,
                                 ServerPort,
                                 Service_type,
                                 Reason])
    end,
    TimeoutFun = fun() ->
        error_logger:error_msg("Timeout on request from ~p:~p of ~p:~p ~p\n",
                                [ClientInfo#client_info.address,
                                 ClientInfo#client_info.port,
                                 ServerAddress,
                                 ServerPort,
                                 Service_type])
    end,
                                
    SenderPID = spawn(?MODULE, handle_scan_results,
                      [OkFun, ErrorFun, TimeoutFun, persp:conf(def_timeout)]),
    dispatch_scanner(SenderPID, ServerInfo);

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% HTTP
handle_request(http, ServerInfo) ->
    dispatch_scanner(self(), ServerInfo),
    handle_scan_results(
        fun(SID, Results) ->
            {ok, persp_http_parser:prepare_response(SID, Results)}
        end,
        fun(Reason) -> {error, Reason} end,
        fun() -> timeout end,
        persp:conf(def_timeout)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Helper functions
dispatch_scanner(SenderPID, ServerInfo) ->
    {_, _, Service_type} = ServerInfo,
    % TODO: this should be read from a configuration file
    case Service_type of
        "2" ->
            {ok, Pid} = get_ssl_scanner(),
            persp_scanner_ssl:start_scan(Pid, {SenderPID, ServerInfo})
    end.

handle_scan_results(OkFun, ErrorFun, TimeoutFun, Timeout) ->
    receive
        {ok, Service_ID, Results} -> apply(OkFun,      [Service_ID, Results]);
        {error, Reason}           -> apply(ErrorFun,   [Reason])
        after Timeout             -> apply(TimeoutFun, [])
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Supervisor behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(ScannerModule) ->
    crypto:start(),
    ssl:start(),
    supervisor:start_link({local, ?MODULE}, ?MODULE, [ScannerModule]).

init([ScannerModule]) ->
    {ok,
        { {simple_one_for_one, persp:conf(max_restart), persp:conf(max_time)},
          [{ scanner,
              {ScannerModule, start_link, []},
              temporary, 2000, worker, []
          }]
        }
    }.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Scanners
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% SSL
get_ssl_scanner() ->
    supervisor:start_child(?MODULE, []).
