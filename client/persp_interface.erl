%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_interface).
-export([start/0]).
-export([add_server/3, del_server/1]).
-export([scan/3, scan_service_id/1]).
-export([print/0]).


start() ->
	gen_server:start_link({local, persp_gs}, persp_gs, [], []).

add_server(IP, Port, Public_Key) ->
	gen_server:call(persp_gs, {add_server, IP, Port, Public_Key}).

del_server(IP) ->
	gen_server:call(persp_gs, {del_server, IP}).

scan(Hostname, Port, Service_Type) ->
	Service_ID = Hostname ++ ":" ++ integer_to_list(Port) ++ "," ++
									integer_to_list(Service_Type),
	scan_service_id(Service_ID).

scan_service_id(Service_ID) ->
	gen_server:call(persp_gs, {scan_service_id, Service_ID}).

print() ->
	gen_server:call(persp_gs, print).
