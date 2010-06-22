%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_scanner_ssh).
-behaviour(gen_fsm).

-define(SOCKET_OPTS, [binary, {reuseaddr, true}, {active, false}]).

%% External API
-export([start_link/0, start_scan/2, rescan_all/0]).

%% gen_fsm callbacks
-export([init/1, terminate/3]).
-export([handle_event/3, handle_info/3, handle_sync_event/4]).
-export([code_change/4]).

%% FSM states
-export(['SCAN'/2]).

%% key_cb callbacks
-export([private_host_rsa_key/2, private_host_dsa_key/2,
         lookup_host_key/3, add_host_key/3]).

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

handle_sync_event(Event, _From, StateName, StateData) ->
    {stop, {StateName, undefined_event, Event}, StateData}.

handle_event(Event, StateName, StateData) ->
    {stop, {StateName, undefined_event, Event}, StateData}.

handle_info(_Info, StateName, StateData) -> {noreply, StateName, StateData}.
terminate(_Reason, _StateName, _State) -> ok.
code_change(_OldVsn, StateName, StateData, _Extr) -> {ok, StateName, StateData}.


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
            error_logger:error_msg("Scan failed\n~s\n", [Reason]),
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
    Service_ID = persp:make_sid(Address, Port, Service_type),
    
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
            Timestamp = persp:time_now(),
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
            Timestamp = persp:time_now(),
            % If merge_cache_entry were asynchronous, it might not update the
            % database in time for sign_entry to fetch the results.
            merge_cache_entry(Service_ID, Fingerprint, Timestamp),
            sign_entry(Service_ID);
        Error ->
            Error
    end.

%% TODO: we seriously need a behaviour.
get_fingerprint(Address, Port) ->
    case ssh:connect(Address, Port, [{replyto, self()} | persp:conf(ssh_opts)],
                     persp:conf(ssh_timeout)) of
        {ok, PID} ->    % either sheer luck or a smarty-pants admin got us in
            ssh:close(PID),
            receive
                {key_fingerprint, Fingerprint} -> {ok, Fingerprint}
            end;
        {error, _HopefullyNotReallyAnError} ->
            receive
                {key_fingerprint, Fingerprint} -> {ok, Fingerprint}
                after persp:conf(ssh_timeout) -> {error, receive_timeout}
            end
    end.

% This spawns a new scanner for each element in the service id list
% TODO: there should be a way to control how many of these go off simultaneously
scan_list(SIDList) ->
    lists:foreach(fun rescan_sid/1, SIDList).

rescan_sid(Service_ID) ->
    {ok, Pid} = persp_scanner_sup_ssh:get_scanner(),
    {Address, Port, _ServiceType} = persp_udp_parser:parse_sid_list(Service_ID),
    rescan(Pid, Service_ID, Address, Port).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Signing
% Since rescan_entry doesn't have all the cached results handy, we pull them
% back from the database.
sign_entry(Service_ID) ->
    Results = check_cache(Service_ID),
    sign_entry(Service_ID, Results).

sign_entry(Service_ID, ScanResults) ->
    SignatureInfo = persp_udp_parser:sign(Service_ID, ScanResults),
    merge_signature(Service_ID, SignatureInfo).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% key_cb - handling the public key sent by the SSH daemon
add_host_key(_Host, Key, Opts) ->
    KeyFingerprint = persp_crypto:key_fingerprint(Key),
    {_replyto, ReplyTo} = lists:keyfind(replyto, 1, Opts),
    ReplyTo ! {key_fingerprint, KeyFingerprint}.

private_host_rsa_key(_, _) -> ok.
private_host_dsa_key(_, _) -> ok.
lookup_host_key(_, _, _) -> {error, not_found}.
