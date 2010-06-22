%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_scanner_sup_ssh).
-behaviour(supervisor).

%% External API
-export([get_scanner/0, handle_scan/2]).

%% Supervisor behaviour callbacks
-export([start_link/0]).
-export([init/1]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
get_scanner() ->
    supervisor:start_child(?MODULE, []).

handle_scan(SenderPID, ServerInfo) ->
    {ok, Pid} = get_scanner(),
    persp_scanner_ssh:start_scan(Pid, {SenderPID, ServerInfo}).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Supervisor behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link() ->
	ssh:start(),
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok,
        { {simple_one_for_one, persp:conf(max_restart), persp:conf(max_time)},
          [ { scanner_ssh,
              {persp_scanner_ssh, start_link, []},
              temporary, 2000, worker, [persp_scanner_ssh]
          } ]
        }
    }.
