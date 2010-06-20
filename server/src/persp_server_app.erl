%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_server_app).
-behaviour(application).

%% Application and Supervisor callbacks
-export([start/2, stop/1, init/1]).

%% TODO: put these in a configuration file
-define(MAX_RESTART,       5).
-define(MAX_TIME,         60).
-define(DEF_HTTP_PORT,  8080).
-define(DEF_UDP_PORT,  15217).
-define(DEF_BINDADDR,  {127,0,0,1}).

% Rescans all database entries every 24 hours
-define(DEF_RESCAN_PERIOD, (24 * 3600 * 1000)).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Application behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start(_Type, _Args) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE,
                          [persp_scanner_ssl,
                           ["../db/sids", "../db/cache", "../db/signatures"]]).

stop(_S) ->
    ok.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Supervisor behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init([ScannerModule, DBFiles]) ->
    {ok,
        {_SupFlags = {one_for_one, ?MAX_RESTART, ?MAX_TIME},
            [
              % UDP Listener
              {   udp_listen,
                  {persp_udp_listener, start_link, [?DEF_UDP_PORT]},
                  permanent,
                  2000,
                  worker,
                  [persp_udp_listener]
              },
              % HTTP Listener
              {   http_listen,
                  {persp_http_listener, start_link, [?DEF_BINDADDR, ?DEF_HTTP_PORT]},
                  permanent,
                  2000,
                  worker,
                  [persp_http_listener]
              },
              % Server that requests rescans
              {   rescan_serv,
                  {rescan_server, start_link, [?DEF_RESCAN_PERIOD, [ScannerModule]]},
                  permanent,
                  2000,
                  worker,
                  [rescan_server]
              },
              % DB server (caches the scan results)
              {   db_serv,
                  {db_server_dets, start_link, [DBFiles]},
                  permanent,
                  2000,
                  worker,
                  []
              },
              % Key signing supervisor
              {   key_serv,
                  {key_sup, start_link, ["../keys/private.pem"]},
                  permanent,
                  infinity,
                  supervisor,
                  []
              },
              % Scanner instance supervisor
              {   scanner_sup,
                  {persp_scanner_sup, start_link, [ScannerModule]},
                  permanent,
                  infinity,
                  supervisor,
                  []
              }
            ]
        }
    }.
