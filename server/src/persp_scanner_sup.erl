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
-export([dispatch_scanner/1]).
-export([get_ssl_scanner/0]).

%% Supervisor behaviour callbacks
-export([start_link/2]).
-export([init/1]).

-define(MAX_RESTART,  5).
-define(MAX_TIME,    60).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
dispatch_scanner(ScanData) ->
	% TODO: come up with better names for ScanInfo and ScanData
	% ScanInfo: {Address, Port, Service_type}
	%			- information about the server
	% ScanData: {ClientSocket, ClientAddress, ClientPort, ClientData}
	%			- information about the client (plus the scan request it sent)
	ScanInfo = {_, _, Service_type} = persp_parser:parse_scan_data(ScanData),
	
	% TODO: perhaps this should be fetched from an ets table, which in turn
	%       is loaded from a config file.
	case Service_type of
		"2" ->
			{ok, Pid} = get_ssl_scanner(),
			persp_scanner_ssl:start_scan(Pid, {ScanInfo, ScanData})
	end.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Supervisor behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(ScannerModule, basic) ->
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
