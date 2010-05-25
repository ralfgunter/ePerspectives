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
-export([handle_request/2]).
-export([get_ssl_scanner/0]).

%% Supervisor behaviour callbacks
-export([start_link/1]).
-export([init/1]).

-define(MAX_RESTART,  5).
-define(MAX_TIME,    60).


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
handle_request(udp, ScanData) ->
    % TODO: come up with better names for ScanInfo and ScanData
    % ScanInfo: {Address, Port, Service_type}
    %           - information about the server
    % ScanData: {ClientSocket, ClientAddress, ClientPort, ClientData}
    %           - information about the client (plus the scan request it sent)
    ScanInfo = {_, _, Service_type} = persp_udp_parser:parse_scandata(ScanData),
    SenderPid = spawn(persp_udp_listener, receive_and_send_results, [ScanData]),
    
    % TODO: perhaps this should be fetched from an ets table, which in turn
    % is loaded from a config file.
    case Service_type of
        "2" ->
            {ok, Pid} = get_ssl_scanner(),
            persp_scanner_ssl:start_scan(Pid, {SenderPid, ScanInfo})
    end;

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% HTTP
handle_request(http, ScanInfo) ->
    {Address, Port, Service_type} = ScanInfo,
    % TODO: this doesn't seem right; investigate.
    SID = Address ++ ":" ++ integer_to_list(Port) ++ "," ++ Service_type,
    
    
    % TODO: perhaps this should be fetched from an ets table, which in turn
    %       is loaded from a config file.
    case Service_type of
        "2" ->
            {ok, Pid} = get_ssl_scanner(),
            persp_scanner_ssl:start_scan(Pid, {self(), ScanInfo})
    end,
    
    receive
        {ok, _Service_ID, Results} ->
            persp_http_parser:prepare_response(SID, Results)
        % TODO: handle scan error and timeout
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
        {_SupFlags = {simple_one_for_one, ?MAX_RESTART, ?MAX_TIME},
            [
              % Scanner
              {   scanner,
                  {ScannerModule, start_link, []},
                  temporary,
                  2000,
                  worker,
                  []
              }
            ]
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
