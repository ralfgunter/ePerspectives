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


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Application behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start(_Type, _Args) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

stop(_S) -> ok.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Supervisor behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init([]) ->
    {ok,
        { {one_for_one, persp:conf(max_restart), persp:conf(max_time)},
          [ % UDP Listener
            { udp_listen,
              { persp_udp_listener, start_link, [persp:conf(udp_port)] },
              permanent, 2000, worker, [persp_udp_listener]
            },
            % HTTP Listener
            { http_listen,
              { persp_http_listener, start_link,
                [persp:conf(bind_addr), persp:conf(http_port)]
              },
              permanent, 2000, worker, [persp_http_listener]
            },
            % Scanner instance supervisor
            { scanner_sup,
              { persp_scanner_sup, start_link, persp:conf(scanner_modules) },
              permanent, infinity, supervisor, []
            },
            % DB server (caches the scan results)
            { db_serv,
              { db_server_dets, start_link, [persp:conf(db_files)] },
              permanent, 2000, worker, [db_server_dets]
            },
            % Key signing supervisor
            { key_serv,
              { key_sup, start_link, [persp:conf(private_key)] },
              permanent, infinity, supervisor, []
            },
            % Server that requests rescans
            { rescan_serv,
              { rescan_server, start_link,
                [persp:conf(rescan_interval), persp:conf(scanner_modules)]
              },
              permanent, 2000, worker, [rescan_server]
            }
          ]
        }
    }.
