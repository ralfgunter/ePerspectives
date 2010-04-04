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

-define(MAX_RESTART,     5).
-define(MAX_TIME,       60).
-define(DEF_PORT,    15217).

% Rescans all database entries every 24 hours
-define(DEF_RESCAN_PERIOD, (24 * 3600 * 1000)).

-define(DEF_CHILDREN, 100).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Application behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start(_Type, _Args) ->
	crypto:start(),
	ssl:start(),
	Port = get_app_env(listen_port, ?DEF_PORT),
	supervisor:start_link({local, ?MODULE}, ?MODULE, [Port, persp_scanner_fsm]).

stop(_S) ->
	ok.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Supervisor behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

init([Port, ScannerModule]) ->
    {ok,
        {_SupFlags = {one_for_one, ?MAX_RESTART, ?MAX_TIME},
            [
              % UDP Listener
              {   udp_listen,
                  {udp_listener, start_link, [Port, ScannerModule]},
                  permanent,
                  2000,
                  worker,
                  [udp_listener]
              },
			  % Server that requests rescans
			  {   rescan_serv,
			      {rescan_server, start_link, [?DEF_RESCAN_PERIOD, [ScannerModule]]},
				  permanent,
				  2000,
				  worker,
				  [rescan_server]
			  },
			  % Key signing supervisor
			  {   key_serv,
			      {key_sup, start_link, ["../keys/private.pem", basic]},
				  permanent,
				  infinity,
				  supervisor,
				  []
			  },
			  % DB server (caches the scan results)
			  {   db_sup,
			      {db_sup, start_link, [db_dets, {"../db/sid_file", "../db/fingerprint_file"}, basic]},
				  permanent,
				  infinity,
				  supervisor,
				  []
			  },
              % Scanner instance supervisor
              {   scanner_sup,
                  {persp_scanner_sup, start_link, [ScannerModule, basic]},
                  permanent,
                  infinity,
                  supervisor,
                  []
              }
            ]
        }
    }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal functions
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
get_app_env(Opt, Default) ->
	case application:get_env(application:get_application(), Opt) of
		{ok, Val} ->
			Val;
		_ ->
			case init:get_argument(Opt) of
				[[Val | _]] ->
					Val;
				error ->
					Default
			end
	end.
