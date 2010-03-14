-module(persp_scanner_fsm).
-behaviour(gen_fsm).
-include_lib("public_key/include/public_key.hrl").

-define(UNIX_EPOCH, 62167219200).
-define(SIG_LEN, 172).
-define(SCAN_TIMEOUT, 5000).
-define(SOCKET_OPTS, [binary, {reuseaddr, true}, {active, false}]).

-export([start_link/0, start_scan/2]).

%% gen_fsm callbacks
-export([init/1, terminate/3]).
-export([handle_event/3, handle_info/3, handle_sync_event/4]).
-export([code_change/4]).

%% FSM states
-export(['SCAN'/2]).

-record(scan_data, {socket, address, port, data}).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% persp_scanner callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link() ->
	gen_fsm:start_link(?MODULE, [], []).

scan(ScanData) ->
	[Domain, Port, Service_type] = parse_scan_data(ScanData),
	
	case ssl:connect(Domain, list_to_integer(Port), ?SOCKET_OPTS) of
		{ok, Socket} ->
			{ok, Cert} = ssl:peercert(Socket),
			KeyFingerprint = crypto:md5(Cert),
			Service_ID = Domain ++ ":" ++ Port ++ "," ++ Service_type,
			
			ssl:close(Socket),
			
			{ok, KeyFingerprint, Service_ID};
		{error, Reason} ->
			error_logger:error_msg("Failed to connect to ~p:~p - ~p\n",
									[Domain, Port, Reason]),
			{error, Reason}
	end.

start_scan(Pid, ScanData) when is_pid(Pid) ->
	gen_fsm:send_event(Pid, {start_scan, ScanData}).

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
		{ok, KeyFingerprint, Service_ID} ->
			BinResponse = prepare_response({KeyFingerprint, Service_ID}),
			send_results(ScanData, BinResponse);
		{error, Reason} ->
			error_logger:error_msg("Scan failed: ~p\n", [Reason])
	end,
	{stop, normal, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Parsing functions
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
parse_scan_data(ScanData) ->
	Data = ScanData#scan_data.data,
	
	<<_:48, Name_len:16, _:16, SIDBin/binary>> = Data,
	
	parse_sid_bin(SIDBin, Name_len).


parse_sid_bin(SIDBin, _Name_len) ->
	SIDList = binary_to_list(SIDBin),
	ParsedSID = string:tokens(SIDList, ":,"),
	
	ParsedSID.


% TODO: check default values.
prepare_response({KeyFingerprint, Service_ID}) ->
	Name_len = length(Service_ID),
	Total_len = 10 + Name_len + 5 + byte_size(KeyFingerprint) + (2 * 4) + ?SIG_LEN,
	
	% TODO: signature length should be customizable - keyserver.
	Header = << 1:8, 3:8, Total_len:16, 9:16, Name_len:16, ?SIG_LEN:16 >>,
	
	LocalTime = erlang:localtime(),
	Seconds = calendar:datetime_to_gregorian_seconds(LocalTime) - ?UNIX_EPOCH,
	
	Key_info = << 1:16, 16:16, 3:8, KeyFingerprint/binary, Seconds:32, Seconds:32 >>,
	SIDBin = list_to_binary(Service_ID),
	Signature = sign(Key_info, SIDBin),
	
	<< Header/binary, SIDBin/binary, Key_info/binary, Signature/binary >>.


sign(Key_info, SIDBin) ->
	Data = << SIDBin/binary, Key_info/binary >>,
	Signature = gen_server:call(key_server, {sign, Data}),
	
	Signature.
