%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

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
		#print_results{output_type = stdout} ->
			{ok, ParsedList} = persp_parser:parse_messages(Result_List),
			pretty_print(ParsedList),
			loop(Server_List, []);
		#scan_results{results = Results} ->
			% TODO: decide whether we join the lists or overwrite the old one
			New_Result_List = Results,
			io:format("Scan is done.\n", []),
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
scan_service_id(From, Service_ID, [{IP, Port, PubKey} | Rest], Results, Socket) ->
	Packet = prepare_header(Service_ID),
	gen_udp:send(Socket, IP, Port, Packet),
	Response = gen_udp:recv(Socket, ?MAX_PACKET_LEN, ?TIMEOUT),
	case Response of
		{ok, _} ->
			scan_service_id(From, Service_ID, Rest, [{Response, PubKey} | Results], Socket);
		{error, Reason} ->
			ErrorWithIP = {error, Reason, IP},
			scan_service_id(From, Service_ID, Rest, [ErrorWithIP | Results], Socket)
	end.

%%
pretty_print([]) ->
	ok;

pretty_print([Head | Rest]) ->
	case Head of
		{Address, Keystamp} ->
			io:format("***** probes from server ~p *****\n", [Address]),
			pretty_print_keys(Keystamp);
		{error, Reason, Address} ->
			io:format("***** probes from server ~p *****\n", [Address]),
			io:format("error: ~p\n\n", [Reason])
	end,
	pretty_print(Rest).

pretty_print_keys([]) ->
	ok;
pretty_print_keys([CurrentKey | Rest]) ->
	{Key, Timestamps} = CurrentKey,
	io:format("key:   ~p\n", [Key]),	% TODO: rewrite this
	pretty_print_timestamps(Timestamps),
	io:format("\n", []),
	pretty_print_keys(Rest).

pretty_print_timestamps([]) ->
	ok;
pretty_print_timestamps([CurrentTimestamp | Rest]) ->
	{Timestamp_begin, Timestamp_end} = CurrentTimestamp,
	io:format("start: ~p\n", [Timestamp_begin]),
	io:format("end:   ~p\n", [Timestamp_end]),
	pretty_print_timestamps(Rest).
