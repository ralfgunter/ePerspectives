%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_interface).
-export([start/0, scan_service_id/1, scan/3, print_results/0, 
		 add_server/3, del_server/1]).
-include("persp_client.hrl").

start() ->
	case whereis(persp_client) of
		undefined ->
			register(persp_client, spawn_link(persp_client, start, []));
		_defined ->
			client_already_started
	end.

scan_service_id(Service_ID) ->
	case whereis(persp_client) of
		undefined ->
			{error, client_not_started};
		_defined ->
			persp_client ! #scan_service_id{service_id = Service_ID}
	end.

scan(Hostname, Port, Service_Type) ->
	case whereis(persp_client) of
		undefined ->
			{error, client_not_started};
		_defined ->
			Service_ID = Hostname ++ ":" ++ integer_to_list(Port) ++ "," ++
											integer_to_list(Service_Type),
			persp_client ! #scan_service_id{service_id = Service_ID}
	end.

print_results() ->
		case whereis(persp_client) of
		undefined ->
			{error, client_not_started};
		_defined ->
			persp_client ! #print_results{output_type = stdout}
	end.

add_server(IP, Port, PubKey) ->
	case whereis(persp_client) of
		undefined ->
			{error, client_not_started};
		_defined ->
			persp_client ! #add_server{ip = IP, port = Port, pubkey = PubKey}
	end.

del_server(IP) ->
	case whereis(persp_client) of
		undefined ->
			{error, client_not_started};
		_defined ->
			persp_client ! #del_server{ip = IP}
	end.
