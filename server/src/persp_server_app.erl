-module(persp_server_app).
-behaviour(application).

%% Internal API
-export([start_scanner/0]).

%% Application and Supervisor callbacks
-export([start/2, stop/1, init/1]).

-define(MAX_RESTART,     5).
-define(MAX_TIME,       60).
-define(DEF_PORT,    15217).

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
              % TCP Listener
              {   udp_listen,                              % Id       = internal id
                  {udp_listener,start_link,[Port,Module]}, % StartFun = {M, F, A}
                  permanent,                               % Restart  = permanent | transient | temporary
                  2000,                                    % Shutdown = brutal_kill | int() >= 0 | infinity
                  worker,                                  % Type     = worker | supervisor
                  [udp_listener]                           % Modules  = [Module] | dynamic
              },
			  % Key server (signing-related functions)
			  {   key_serv,
			      {key_server, start_link, ["keys/private_key.pem", "keys/public_key.pem"]},
				  permanent,
				  brutal_kill,
				  worker,
				  [key_server]
			  },
              % Client instance supervisor
              {   persp_scanner_sup,
                  {supervisor,start_link,[{local, persp_scanner_sup}, ?MODULE, [Module]]},
                  permanent,                               % Restart  = permanent | transient | temporary
                  infinity,                                % Shutdown = brutal_kill | int() >= 0 | infinity
                  supervisor,                              % Type     = worker | supervisor
                  []                                       % Modules  = [Module] | dynamic
              }
            ]
        }
    };


init([Module]) ->
    {ok,
        {_SupFlags = {simple_one_for_one, ?MAX_RESTART, ?MAX_TIME},
            [
              % TCP Client
              {   undefined,                               % Id       = internal id
                  {Module,start_link,[]},                  % StartFun = {M, F, A}
                  temporary,                               % Restart  = permanent | transient | temporary
                  2000,                                    % Shutdown = brutal_kill | int() >= 0 | infinity
                  worker,                                  % Type     = worker | supervisor
                  []                                       % Modules  = [Module] | dynamic
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
