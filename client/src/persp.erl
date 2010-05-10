%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp).

-export([add_server/2, del_server/2]).
-export([scan/2, pretty_print/1]).

-define(DEFAULT_PORT,   12345).
-define(MAX_PACKET_LEN,  4000).
-define(TIMEOUT,         8000).
-define(SIG_LEN,          172).
-define(UDP_OPTIONS, [binary, {active, false}, {reuseaddr, true}]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Server management
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Adds a new server to the servers list
add_server({Address, Port, Public_Key, Server_type}, Servers) ->
    case lists:keymember(Address, 1, Servers) of
        true ->
            NewServers = Servers,
            Response = server_already_listed;
        false ->
            NewServers = [{Address, Port, Public_Key, Server_type} | Servers],
            Response = ok
    end,
    {Response, NewServers}.


%% Deletes a server from the servers list
del_server(Address, Servers) ->
    case lists:keymember(Address, 1, Servers) of
        true ->
            NewServers = lists:keydelete(Address, 1, Servers),
            Response = ok;
        false ->
            NewServers = Servers,
            Response = server_not_listed
    end,
    {Response, NewServers}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Scanning
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
scan(ScanHeader, Servers) ->
    Packet = prepare_header(build_sidbin(ScanHeader)),
    
    Lambda = fun(Server, Results) ->
        [raw_scan(Packet, Server) | Results]
    end,
    Results = lists:foldl(Lambda, [], Servers),
    
    {ok, Results}.


raw_scan(Packet, {ServAddress, ServPort, Public_Key, udp}) ->
    {ok, Socket} = gen_udp:open(?DEFAULT_PORT, ?UDP_OPTIONS),
    gen_udp:send(Socket, ServAddress, ServPort, Packet),
    Response = gen_udp:recv(Socket, ?MAX_PACKET_LEN, ?TIMEOUT),
    ok = gen_udp:close(Socket),
    
    case Response of
        {ok, {_Address, _Port, Data}} ->
            {udp, {ServAddress, ServPort, Public_Key, Data}};
        {error, Reason} ->
            {udp, {error, Reason, ServAddress}}
    end.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Printing
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% To stdout
pretty_print([]) ->
    ok;

pretty_print([{ServerType, Head} | Rest]) ->
    ServerTypeList = atom_to_list(ServerType),
    
    case Head of
        {Address, Keystamp} ->
            io:format("***** probes from server ~p (~p) *****\n",
                      [Address, ServerTypeList]),
            pretty_print_keys(Keystamp);
        {error, Reason, Address} ->
            io:format("***** probes from server ~p (~p) *****\n",
                      [Address, ServerTypeList]),
            io:format("error: ~p\n\n", [Reason])
    end,
    pretty_print(Rest).

pretty_print_keys([]) ->
    ok;
pretty_print_keys([CurrentKey | Rest]) ->
    {Key, Timestamps} = CurrentKey,
    io:format("key:   ~p\n", [Key]),    % TODO: rewrite this
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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Prepares scan request header.
prepare_header(SIDBin) ->
    Len = byte_size(SIDBin),
    
    %% (struct member):(size in bits)
    % version:8, msg_type:8, total_len:16, service_type:16, name_len:16,
    % sig_len:8, (Service_ID):(Len)
    << 1:8, 1:8, (10 + Len):16, 9:16, Len:16, ?SIG_LEN:16, SIDBin/binary >>.

build_sidbin({Address, Port, Service_type}) ->
    Mod_SID = Address ++ ":" ++ integer_to_list(Port) ++ ","
                             ++ integer_to_list(Service_type) ++ "\x00",
    
    list_to_binary(Mod_SID).
