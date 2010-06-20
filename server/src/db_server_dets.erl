%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(db_server_dets).
-behaviour(gen_server).

%% External API
-export([start_link/1]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_server callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(DBFiles) ->
    gen_server:start_link({local, db_serv}, ?MODULE, DBFiles, []).

init(DBFiles) ->
    load_db_files(DBFiles),
    
    {ok, {}}.

terminate(_Reason, _State) ->
    dets:close(sids),
    dets:close(cache),
    dets:close(signatures).

code_change(_OldVersion, State, _Extra) ->
    {ok, State}.

handle_info(_Info, State) ->
    {noreply, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Cast handling (asynchronous commands)
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
handle_cast({add_cache_entry, Service_ID, Fingerprint, Timestamp}, State) ->
    add_cache_entry(Service_ID, Fingerprint, Timestamp),
    {noreply, State};

handle_cast({merge_signature, Service_ID, SignatureInfo}, State) ->
    merge_signature(Service_ID, SignatureInfo),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Call handling
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% See persp_scanner_ssl:rescan_entry for why this has to be synchronous.
handle_call({merge_cache_entry, Service_ID, Fingerprint, Timestamp}, _From, State) ->
    merge_cache_entry(Service_ID, Fingerprint, Timestamp),
    {reply, ok, State};

handle_call({check_cache, Service_ID}, _From, State) ->
    Cache = check_cache(Service_ID),
    {reply, Cache, State};

handle_call(list_all_sids, _From, State) ->
    List = list_all_sids(),
    {reply, List, State};

handle_call({get_signature, Service_ID}, _From, State) ->
    SignatureInfo = get_signature(Service_ID),
    {reply, SignatureInfo, State};

handle_call(Request, _From, State) ->
    {stop, {unknown_call, Request}, State}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Queries
add_cache_entry(Service_ID, Fingerprint, Timestamp) ->
    insert_fingerprint(Service_ID, Fingerprint),
    insert_timestamp(Service_ID, Fingerprint, Timestamp, Timestamp, []).

check_cache(Service_ID) ->
    case dets:member(sids, Service_ID) of
        true ->
            Fingerprints = list_fingerprints(Service_ID),
            Timestamps   = list_timestamps(Service_ID, Fingerprints),
            ResultPairs  = lists:zip(Fingerprints, Timestamps),
            
            ResultPairs;
        false ->
            []
    end.

list_all_sids() ->
    % TODO: find a function that lists all the keys in a table.
    ResultPairs = dets:match(sids, {'$1', _ = '_'}),
    
    lists:append(ResultPairs).

% There are two possible cases here:
%     1) The fingerprint is the same as the current one
%     2) The fingerprint is not the same as the current one
%
% In the second case, there are two additional possibilities:
%     2.1) The new fingerprint is already in the database
%     2.2) The new fingerprint is not yet in the database
%
% 1 would require a simple update_entry call. However, 2 is a bit trickier.
% Unfortunately, add_cache_entry only handles 2.2, but 2.1 might happen if, for
% example, the server being tested alternates certificates (e.g. Google).
merge_cache_entry(Service_ID, Fingerprint, Timestamp) ->
    LastFingerprint = get_most_recent_fingerprint(Service_ID),
    
    update_entry(Service_ID, LastFingerprint, Timestamp),
    
    case Fingerprint of
        LastFingerprint ->
            ok;
        _AnotherFingerprint ->
            case dets:member(cache, {Service_ID, Fingerprint}) of
                true ->
                    add_timestamp(Service_ID, Fingerprint,
                                  Timestamp + 1, Timestamp + 1);
                false ->
                    add_cache_entry(Service_ID, Fingerprint, Timestamp + 1)
            end
    end.

get_signature(Service_ID) ->
    [{_Service_ID, SignatureInfo}] = dets:lookup(signatures, Service_ID),
    
    SignatureInfo.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Database internal representation
insert_timestamp(Service_ID, Fingerprint, Beginning, End, Rest) ->
    dets:insert(cache, { {Service_ID, Fingerprint},
                         [ {Beginning, End} | Rest ]
                       }).

insert_fingerprint(Service_ID, Fingerprint) ->
    dets:insert(sids, {Service_ID, Fingerprint}).

get_timestamps(Service_ID, Fingerprint) ->
    [{_Key, Timestamps}] = dets:lookup(cache, {Service_ID, Fingerprint}),
    
    Timestamps.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Fingerprints
list_fingerprints(Service_ID) ->
    % TODO: find a function that's as lightweight as lookup, but returns only
    % the matching objects' values, instead of the entire object.
    SIDFingerprints = dets:lookup(sids, Service_ID),
    
    lists:map(fun({_SID, Fingerprint}) -> Fingerprint end, SIDFingerprints).

get_most_recent_fingerprint(Service_ID) ->
    [Head | Rest] = check_cache(Service_ID),
    {Fingerprint, _Timestamps} = lists:foldl(fun last_timestamp/2, Head, Rest),
    
    Fingerprint.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Timestamps
list_timestamps(Service_ID, Fingerprints) ->
    lists:map(fun(F) -> get_timestamps(Service_ID, F) end, Fingerprints).

add_timestamp(Service_ID, Fingerprint, Beginning, End) ->
    Timestamps = get_timestamps(Service_ID, Fingerprint),
    insert_timestamp(Service_ID, Fingerprint, Beginning, End, Timestamps).

last_timestamp(CurrentTimestamp, BiggestYet) ->
    {_, [{_, BiggestEnd} | _]} = BiggestYet,
    {_, [{_, CurrentEnd} | _]} = CurrentTimestamp,
    
    if
        CurrentEnd > BiggestEnd -> CurrentTimestamp;
        true -> BiggestYet
    end.

update_timestamps(Service_ID, Fingerprint, Timestamps, NewEnd) ->
    [{Beg, _OldEnd} | Rest] = Timestamps,
    insert_timestamp(Service_ID, Fingerprint, Beg, NewEnd, Rest).

update_entry(Service_ID, Fingerprint, NewEnd) ->
    Timestamps = get_timestamps(Service_ID, Fingerprint),
    update_timestamps(Service_ID, Fingerprint, Timestamps, NewEnd).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Signatures
% SignatureInfo is of the following format:
%     {SignatureBinary, SignatureAlgorithm, SignatureLength}
% Where:
%     - SignatureBinary is the signature itself
%     - SignatureAlgorithm can either be {rsa, md5} or {rsa, sha}
%     - SignatureLength    currently can only be 172 (bytes)

% This can both insert a new signature to the cache and update an old one.
merge_signature(Service_ID, SignatureInfo) ->
    dets:insert(signatures, {Service_ID, SignatureInfo}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Database initialization and loading
load_db_files([Sids_filename, Cache_filename, Signatures_filename]) ->
    dets:open_file(sids,       [{file, Sids_filename}, {type, bag}]),
    dets:open_file(cache,      [{file, Cache_filename}]),
    dets:open_file(signatures, [{file, Signatures_filename}]).
