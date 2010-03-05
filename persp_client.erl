-module(persp_client).
-export([start/0, scan_service_id/4]).

-include("persp_client.hrl").

start() ->
	loop([], []).

loop(Server_List, Result_List) ->
	receive
		#add_server{ip = IP, port = Port, pubkey = PubKey} ->
			New_Server_List = add_server(IP, Port, PubKey, Server_List),
			loop(New_Server_List, Result_List);
		#del_server{ip = IP} ->
			New_Server_List = del_server(IP, Server_List),
			loop(New_Server_List, Result_List);
		#scan_service_id{service_id = Service_ID} ->
			{ok, Socket} = gen_udp:open(?DEFAULT_PORT, ?UDP_OPTIONS),
			spawn_link( ?MODULE, scan_service_id,
						[self(), Service_ID, Server_List, Socket] ),
			loop(Server_List, Result_List);
		{print_results} ->
			{ok, ParsedList} = persp_parser:parse_messages(Result_List),
			pretty_print(ParsedList),
			loop(Server_List, []);
		#scan_results{results = Results} ->
			% TODO: decide whether we join the lists or overwrite the old one
			New_Result_List = Results,
			loop(Server_List, New_Result_List)
	end.

%% Adds a notary server to the servers list
add_server(IP, Port, PubKey, Server_List) ->
	case lists:keymember(IP, 1, Server_List) of
		true ->
			io:format("Server ~p is already listed\n", [IP]),
			Server_List;
		false ->
			io:format("Server ~p added to the list\n", [IP]),
			[{IP, Port, PubKey} | Server_List]
	end.

%% Deletes a server from the servers list
del_server(IP, Server_List) ->
	lists:keydelete(IP, 1, Server_List).

%% Prepares scan request header
prepare_header(Service_ID) ->
	SIDBin = list_to_binary(Service_ID ++ "\x00"),
	Len = byte_size(SIDBin),
	%% (struct member):(size in bits)
	% version:8, msg_type:8, total_len:16, service_type:16, name_len:16,
	% sig_len:8, (Service_ID):(Len)
	<< 1:8, 1:8, (10 + Len):16, 9:16, Len:16, ?SIG_LEN:16, SIDBin/binary >>.

%% Sends a scan request to the notary server
scan_service_id(From, Service_ID, Server_List, Socket) ->
	scan_service_id(From, Service_ID, Server_List, [], Socket).

scan_service_id(From, _Service_ID, [], Results, _Socket) ->
	From ! #scan_results{results = Results};
scan_service_id(From, Service_ID, [{IP, Port, _PubKey} | Rest], Results, Socket) ->
	Packet = prepare_header(Service_ID),
	gen_udp:send(Socket, IP, Port, Packet),
	Response = gen_udp:recv(Socket, ?MAX_PACKET_LEN, ?TIMEOUT),
	scan_service_id(From, Service_ID, Rest, [Response | Results], Socket).

%%
pretty_print([]) ->
	ok;

pretty_print([Head | Rest]) ->
	{Address, Keystamp} = Head,
	io:format("server address: ~p\n", [Address]),
	pretty_print_keystamp(Keystamp),
	pretty_print(Rest).

pretty_print_keystamp([]) ->
	ok;
pretty_print_keystamp([CurrentKeystamp | Rest]) ->
	{Key, Timestamp_begin, Timestamp_end} = CurrentKeystamp,
	io:format("key: ~p\n", [Key]),	% TODO: rewrite this
	io:format("timestamp begin: ~p\n", [Timestamp_begin]),
	io:format("timestamp end: ~p\n\n", [Timestamp_end]),
	pretty_print_keystamp(Rest).
