%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_scanner_fsm).
-behaviour(gen_fsm).

-define(UNIX_EPOCH, 62167219200).
-define(SIG_LEN, 172).
-define(SCAN_TIMEOUT, 5000).
-define(SOCKET_OPTS, [binary, {reuseaddr, true}, {active, false}]).

-export([start_link/0, start_scan/2, rescan_all/0]).

%% gen_fsm callbacks
-export([init/1, terminate/3]).
-export([handle_event/3, handle_info/3, handle_sync_event/4]).
-export([code_change/4]).

%% FSM states
-export(['SCAN'/2]).

-record(scan_data, {socket, address, port, data}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link() ->
	gen_fsm:start_link(?MODULE, [], []).

start_scan(Pid, ScanData) when is_pid(Pid) ->
	gen_fsm:send_event(Pid, {start_scan, ScanData}).

rescan(Pid, Service_ID, Domain, Port) when is_pid(Pid) ->
	gen_fsm:send_event(Pid, {rescan, Service_ID, Domain, Port}).

rescan_all() ->
	SIDList = get_sid_list(),
	scan_list(SIDList).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_fsm callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init(_Args) ->
	{ok, 'SCAN', #scan_data{}}.

handle_info(_Info, StateName, StateData) ->
	{noreply, StateName, StateData}.

handle_sync_event(Event, _From, StateName, StateData) ->
	{stop, {StateName, undefined_event, Event}, StateData}.

handle_event(Event, StateName, StateData) ->
	{stop, {StateName, undefined_event, Event}, StateData}.

terminate(_Reason, _StateName, _State) ->
	% TODO: Do away with this.
	% There should be no need for a scanner to explicitly (in contrast to the
	% regular erlang methods) inform the supervisor that it has terminated.
	% This is probably inefficient in a large scale and ties the implementation
	% of the child with the supervisor's.
	persp_scanner_sup:child_terminated(self()),
	ok.

code_change(_OldVsn, StateName, StateData, _Extra) ->
	{ok, StateName, StateData}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% FSM States
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
'SCAN'({start_scan, ScanData}, State) ->
	case scan(ScanData) of
		{ok, Service_ID, Results} ->
			BinResponse = prepare_response(Service_ID, Results),
			send_results(ScanData, BinResponse);
		{error, Reason} ->
			error_logger:error_msg("Scan failed: ~p\n", [Reason])
	end,
	{stop, normal, State};

'SCAN'({rescan, Service_ID, Domain, Port}, State) ->
	rescan_entry(Service_ID, Domain, Port),
	{stop, normal, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Parsing
parse_scan_data(ScanData) ->
	Data = ScanData#scan_data.data,
	
	<<_:48, Name_len:16, _:16, SIDBin/binary>> = Data,
	
	parse_sid_bin(SIDBin, Name_len).

parse_sid_bin(SIDBin, _Name_len) ->
	SIDList = binary_to_list(SIDBin),
	ParsedSID = string:tokens(SIDList, ":,"),
	
	ParsedSID.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Preparing the response to a scan request
prepare_response(Service_ID, List) ->
	Num_entries = length(List),
	prepare_response(Service_ID, List, << Num_entries:16, 16:16, 3:8 >>).

% This is called when we're done parsing all {fingerprint, timestamps} entries
prepare_response(Service_ID, [], Key_info) ->
	Name_len  = length(Service_ID),
	Total_len = 10 + Name_len + byte_size(Key_info) + ?SIG_LEN,
	
	% TODO: signature length should be customizable - keyserver.
	Header = << 1:8, 3:8, Total_len:16, 9:16, Name_len:16, ?SIG_LEN:16 >>,
	
	SIDBin = list_to_binary(Service_ID),
	Signature = sign(Key_info, SIDBin),
	
	<< Header/binary, SIDBin/binary, Key_info/binary, Signature/binary >>;

% This is called once per fingerprint
prepare_response(Service_ID, [CurrentEntry | Rest], Results) ->
	{Fingerprint, Timestamps} = CurrentEntry,
	
	BinTimestamps = prepare_timestamps(Timestamps),
	Data = << Fingerprint/binary, BinTimestamps/binary >>,
	
	prepare_response(Service_ID, Rest, << Results/binary, Data/binary >>).

prepare_timestamps(Timestamps) ->
	prepare_timestamps(Timestamps, <<>>).

% This is called once we're done parsing timestamps
prepare_timestamps([], Results) ->
	Results;

% This is called once per timestamp
prepare_timestamps([CurrentPair | Rest], Results) ->
	[Timestamp_beg, Timestamp_end] = CurrentPair,
	
	NewResults = << Results/binary, Timestamp_beg:32, Timestamp_end:32 >>,
	
	prepare_timestamps(Rest, NewResults).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Database access
check_cache(Service_ID) ->
	gen_server:call(db_server_dets, {check_cache, Service_ID}).

add_entry(Service_ID, Fingerprint, Timestamp) ->
	gen_server:call(db_server_dets, {add_entry, Service_ID, Fingerprint, Timestamp}).

update_entry(Fingerprint, NewTimestamp) ->
	gen_server:call(db_server_dets, {update_entry, Fingerprint, NewTimestamp}).

get_sid_list() ->
	gen_server:call(db_server_dets, {list_all_sids}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Scanning
scan(ScanData) ->
	[Domain, Port, Service_type] = parse_scan_data(ScanData),
	scan(Domain, Port, Service_type).

scan(Domain, Port, Service_type) ->
	Service_ID = Domain ++ ":" ++ Port ++ "," ++ Service_type,
	IntegerPort = list_to_integer(Port),
	
	case check_cache(Service_ID) of
		[] ->
			Result = new_scan(Service_ID, Domain, IntegerPort),
			
			{ok, Service_ID, [Result]};
		Results ->
			{ok, Service_ID, Results}
	end.

new_scan(Service_ID, Domain, Port) ->
	{ok, Fingerprint} = get_fingerprint(Domain, Port),
	Timestamp = time_now(),
	add_entry(Service_ID, Fingerprint, Timestamp),
	Result = {Fingerprint, [[Timestamp, Timestamp]]},
	
	Result.

rescan_entry(_Service_ID, Domain, Port) ->
	{ok, Fingerprint} = get_fingerprint(Domain, Port),
	Timestamp = time_now(),
	update_entry(Fingerprint, Timestamp).

get_fingerprint(Domain, Port) ->
	case ssl:connect(Domain, Port, ?SOCKET_OPTS) of
		{ok, Socket} ->
			{ok, Cert} = ssl:peercert(Socket),
			KeyFingerprint = crypto:md5(Cert),
			
			ssl:close(Socket),
			
			{ok, KeyFingerprint};
		{error, Reason} ->
			error_logger:error_msg("Failed to connect to ~p:~p - ~p\n",
									[Domain, Port, Reason]),
			{error, Reason}
	end.

% This spawns a new scanner for each element in the list
% TODO: there should be a way to control how many of these go off simultaneously
scan_list([]) ->
	ok;

scan_list([[CurrentSID] | Rest]) ->
	{ok, Pid} = persp_scanner_sup:get_scanner(),
	[Domain, Port, _Service_type] = string:tokens(CurrentSID, ":,"),
	IntPort = list_to_integer(Port),
	rescan(Pid, CurrentSID, Domain, IntPort),
	scan_list(Rest).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Misc
sign(Key_info, SIDBin) ->
	Data = << SIDBin/binary, Key_info/binary >>,
	Signature = sign_data(Data),
	
	Signature.

sign_data(Data) ->
	%gen_server:call(key_server, {sign, Data}).
	
	{ok, Pid} = key_sup:get_signer(),
	key_signer:start_to_sign(Pid, Data, self()),
	receive
		{ok, SignedData} ->
			SignedData
	end.

time_now() ->
	LocalTime = erlang:localtime(),
	Seconds = calendar:datetime_to_gregorian_seconds(LocalTime) - ?UNIX_EPOCH,
	
	Seconds.

send_results(ScanData, Results) ->
	ClientSocket  = ScanData#scan_data.socket,
	ClientAddress = ScanData#scan_data.address,
	ClientPort    = ScanData#scan_data.port,
	
	case gen_udp:send(ClientSocket, ClientAddress, ClientPort, Results) of
		ok ->
			ok;
		{error, Reason} ->
			error_logger:error_msg("Failed to send results: ~p\n", [Reason])
	end.
