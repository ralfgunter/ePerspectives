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
			persp_client ! {print_results}
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
