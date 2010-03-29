%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_server_app).
-behaviour(application).

%% Internal API
-export([start_scanner/0]).

%% Application and Supervisor callbacks
-export([start/2, stop/1, init/1]).

-define(MAX_RESTART,     5).
-define(MAX_TIME,       60).
-define(DEF_PORT,    15217).

% Rescans all database entries every 24 hours
-define(DEF_RESCAN_PERIOD, (24 * 3600 * 1000)).

%% A startup function for spawning a new scanner FSM.
%% To be called by the UDP listener process.
start_scanner() ->
	supervisor:start_child(persp_scanner_sup, []).

%%----------------------------------------------------------------------
%% Application behaviour callbacks
%%----------------------------------------------------------------------
start(_Type, _Args) ->
	crypto:start(),
	ssl:start(),
	Port = get_app_env(listen_port, ?DEF_PORT),
	supervisor:start_link({local, ?MODULE}, ?MODULE, [Port, persp_scanner_fsm]).

stop(_S) ->
	ok.

%%----------------------------------------------------------------------
%% Supervisor behaviour callbacks
%%----------------------------------------------------------------------

init([Port, Module]) ->
    {ok,
        {_SupFlags = {one_for_one, ?MAX_RESTART, ?MAX_TIME},
            [
              % UDP Listener
              {   udp_listen,
                  {udp_listener,start_link,[Port,Module]},
                  permanent,
                  2000,
                  worker,
                  [udp_listener]
              },
			  % Key server (signing-related functions)
			  {   key_serv,
			      {key_server, start_link, ["../keys/private.pem", "../keys/public.pem"]},
				  permanent,
				  brutal_kill,
				  worker,
				  [key_server]
			  },
			  % DB server (caches the scan results)
			  {   db_serv,
			      {db_server_dets, start_link, ["../db/sid_file", "../db/fingerprint_file"]},
				  permanent,
				  2000,
				  worker,
				  [db_server_dets]
			  },
			  % Server that requests rescans
			  {   rescan_serv,
			      {rescan_server, start_link, [?DEF_RESCAN_PERIOD, [Module]]},
				  permanent,
				  2000,
				  worker,
				  [rescan_server]
			  },
              % Scanner instance supervisor
              {   persp_scanner_sup,
                  {supervisor,start_link,[{local, persp_scanner_sup}, ?MODULE, [Module]]},
                  permanent,
                  infinity,
                  supervisor,
                  []
              }
            ]
        }
    };


init([Module]) ->
    {ok,
        {_SupFlags = {simple_one_for_one, ?MAX_RESTART, ?MAX_TIME},
            [
              % Scanner
              {   scanner,
                  {Module,start_link,[]},
                  temporary,
                  2000,
                  worker,
                  []
              }
            ]
        }
    }.


%%----------------------------------------------------------------------
%% Internal functions
%%----------------------------------------------------------------------
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
