%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp).
-export([add_server/4, del_server/2]).
-export([prepare_header/1, scan_service_id/3, pretty_print/1]).

-include("persp.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%% Server management functions

%% Adds a new server to the servers list
add_server(IP, Port, Public_Key, Servers) ->
	case lists:keymember(IP, 1, Servers) of
		true ->
			NewServers = Servers,
			Response = server_already_listed;
		false ->
			NewServers = [{IP, Port, Public_Key} | Servers],
			Response = ok
	end,
	{Response, NewServers}.


%% Deletes a server from the servers list
del_server(IP, Servers) ->
	case lists:keymember(IP, 1, Servers) of
		true ->
			NewServers = lists:keydelete(IP, 1, Servers),
			Response = ok;
		false ->
			NewServers = Servers,
			Response = server_not_listed
	end,
	{Response, NewServers}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%% Networking functions

%% Prepares scan request header.
prepare_header(Service_ID) ->
	SIDBin = list_to_binary(Service_ID ++ "\x00"),
	Len = byte_size(SIDBin),
	%% (struct member):(size in bits)
	% version:8, msg_type:8, total_len:16, service_type:16, name_len:16,
	% sig_len:8, (Service_ID):(Len)
	<< 1:8, 1:8, (10 + Len):16, 9:16, Len:16, ?SIG_LEN:16, SIDBin/binary >>.


%% Sends a scan request to the notary server.
scan_service_id(Service_ID, Server_List, Socket) ->
	scan_service_id(Service_ID, Server_List, [], Socket).

scan_service_id(_Service_ID, [], Results, _Socket) ->
	{ok, Results};
scan_service_id(Service_ID, [{IP, Port, PubKey} | Rest], Results, Socket) ->
	Packet = prepare_header(Service_ID),
	gen_udp:send(Socket, IP, Port, Packet),
	Response = gen_udp:recv(Socket, ?MAX_PACKET_LEN, ?TIMEOUT),
	case Response of
		{ok, {_Address, _Port, Data}} ->
			NewResults = [{IP, Port, PubKey, Data} | Results],
			scan_service_id(Service_ID, Rest, NewResults, Socket);
		{error, Reason} ->
			ErrorWithIP = {error, Reason, IP},
			scan_service_id(Service_ID, Rest, [ErrorWithIP | Results], Socket)
	end.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%% Printing functions

%% Prints the scan results to stdout.
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
