%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_scanner_ssl).
-behaviour(gen_fsm).

-define(UNIX_EPOCH, 62167219200).
-define(SCAN_TIMEOUT, 5000).
-define(SOCKET_OPTS, [binary, {reuseaddr, true}, {active, false}]).

%% External API
-export([start_link/0, start_scan/2, rescan_all/0]).

%% gen_fsm callbacks
-export([init/1, terminate/3]).
-export([handle_event/3, handle_info/3, handle_sync_event/4]).
-export([code_change/4]).

%% FSM states
-export(['SCAN'/2]).

-record(client_info, {socket, address, port, data}).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link() ->
    gen_fsm:start_link(?MODULE, [], []).

start_scan(Pid, ScanPair) when is_pid(Pid) ->
    gen_fsm:send_event(Pid, {start_scan, ScanPair}).

rescan(Pid, Service_ID, Address, Port) when is_pid(Pid) ->
    gen_fsm:send_event(Pid, {rescan, Service_ID, Address, Port}).

rescan_all() ->
    scan_list(get_sid_list()).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_fsm callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init(_Args) ->
    {ok, 'SCAN', #client_info{}}.

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
'SCAN'({start_scan, {RequestorPID, ScanInfo}}, State) ->
    case scan(ScanInfo) of
        {ok, Service_ID, Results} ->
            RequestorPID ! {ok, Service_ID, Results};
        {error, Reason} ->
            error_logger:error_msg("Scan failed\n~p\n", [Reason]),
            RequestorPID ! {error, Reason}
    end,
    {stop, normal, State};

'SCAN'({rescan, Service_ID, Address, Port}, State) ->
    rescan_entry(Service_ID, Address, Port),
    {stop, normal, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Database access
add_cache_entry(Service_ID, Fingerprint, Timestamp) ->
    gen_server:cast(db_serv,
                    {add_cache_entry, Service_ID, Fingerprint, Timestamp}).

merge_cache_entry(Service_ID, Fingerprint, Timestamp) ->
    gen_server:call(db_serv,
                    {merge_cache_entry, Service_ID, Fingerprint, Timestamp}).

merge_signature(Service_ID, SignatureInfo) ->
    gen_server:cast(db_serv,
                    {merge_signature, Service_ID, SignatureInfo}).

check_cache(Service_ID) ->
    gen_server:call(db_serv,
                    {check_cache, Service_ID}).

get_sid_list() ->
    gen_server:call(db_serv,
                    list_all_sids).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Scanning
scan({Address, Port, Service_type}) ->
    Service_ID = Address ++ ":" ++ integer_to_list(Port) ++ "," ++ Service_type,
    
    case check_cache(Service_ID) of
        [] ->
            case new_scan(Service_ID, Address, Port) of
                {ok, Result} ->
                    {ok, Service_ID, [Result]};
                Error ->
                    Error
            end;
        Results ->
            {ok, Service_ID, Results}
    end.

new_scan(Service_ID, Address, Port) ->
    case get_fingerprint(Address, Port) of
        {ok, Fingerprint} ->
            Timestamp = time_now(),
            %% TODO: abstract this
            ScanResult = {Fingerprint, [{Timestamp, Timestamp}]},
            
            add_cache_entry(Service_ID, Fingerprint, Timestamp),
            sign_entry(Service_ID, [ScanResult]),
            
            {ok, ScanResult};
        Error ->
            Error
    end.

rescan_entry(Service_ID, Address, Port) ->
    case get_fingerprint(Address, Port) of
        {ok, Fingerprint} ->
            Timestamp = time_now(),
            % If merge_cache_entry were asynchronous, it might not update the
            % database in time for sign_entry to fetch the results.
            merge_cache_entry(Service_ID, Fingerprint, Timestamp),
            sign_entry(Service_ID);
        Error ->
            Error
    end.

get_fingerprint(Address, Port) ->
    case ssl:connect(Address, Port, ?SOCKET_OPTS) of
        {ok, Socket} ->
            {ok, Certificate} = ssl:peercert(Socket),
            KeyFingerprint = crypto:md5(Certificate),
            
            ssl:close(Socket),
            
            {ok, KeyFingerprint};
        {error, Reason} ->
            error_logger:error_msg("Failed to connect to ~p:~p\n~p\n",
                                   [Address, Port, Reason]),
            {error, Reason}
    end.

% This spawns a new scanner for each element in the list
% TODO: there should be a way to control how many of these go off simultaneously
scan_list(SIDList) ->
    lists:foreach(fun rescan_sid/1, SIDList).

rescan_sid(Service_ID) ->
    {ok, Pid} = persp_scanner_sup:get_ssl_scanner(),
    {Address, Port, _} = persp_udp_parser:parse_sid_list(Service_ID),
    rescan(Pid, Service_ID, Address, Port).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Signing
% Since rescan_entry doesn't have all the cached results handy, we pull them
% back from the database.
sign_entry(Service_ID) ->
    Results = check_cache(Service_ID),
    SignatureInfo = persp_udp_parser:sign(Service_ID, Results),
    merge_signature(Service_ID, SignatureInfo).

sign_entry(Service_ID, ScanResults) ->
    SignatureInfo = persp_udp_parser:sign(Service_ID, ScanResults),
    merge_signature(Service_ID, SignatureInfo).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Misc
time_now() ->
    LocalTime = erlang:localtime(),
    Seconds = calendar:datetime_to_gregorian_seconds(LocalTime) - ?UNIX_EPOCH,
    
    Seconds.
