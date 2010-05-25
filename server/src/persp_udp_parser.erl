%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_udp_parser).

-define(SIG_LEN, 172).

-export([parse_scandata/1, parse_sid_list/1]).
-export([prepare_response/2]).
-export([sign/2]).

-record(scan_data, {socket, address, port, data}).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Parsing
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
parse_scandata(ScanData) ->
    << _:80, SIDBin/binary >> = ScanData#scan_data.data,
    
    parse_sid_bin(SIDBin).

parse_sid_list(SIDList) ->
    % Here the last element of Service_type is a NULL, which must be removed in
    % this module because all other modules using it assume it's not there.
    [Address, StrPort, [Service_type, 0]] = string:tokens(SIDList, ":,"),
    
    {Address, list_to_integer(StrPort), [Service_type]}.

parse_sid_bin(SIDBin) ->
    SIDList = binary_to_list(SIDBin),
    
    parse_sid_list(SIDList).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Preparing the response
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
prepare_response(Service_ID, ScanResults) ->
    finalize_response(Service_ID, prepare_key_info(ScanResults)).

% An explanation of the values used below is available in the client udp parser
% code: client/src/persp_udp_parser.erl
finalize_response(Service_ID, Key_info) ->
    SIDBin = list_to_binary(Service_ID),
    {SigBin, _SigAlgorithm, SigLen} = request_signature(Service_ID),
    
    Name_len  = length(Service_ID),
    Total_len = 10 + Name_len + byte_size(Key_info) + SigLen,
    
    Header = << 1:8, 3:8, Total_len:16, 9:16, Name_len:16, SigLen:16 >>,
    
    << Header/binary, SIDBin/binary, Key_info/binary, SigBin/binary >>.

prepare_key_info(ScanResults) ->
    Num_entries = length(ScanResults),
    InitialHeader = << Num_entries:16, 16:16, 3:8 >>,
    
    lists:foldl(fun prepare_fingerprint/2, InitialHeader, ScanResults).

prepare_fingerprint({Fingerprint, Timestamps}, ResultsSoFar) ->
    BinTimestamps = prepare_timestamps(Timestamps),
    
    << ResultsSoFar/binary, Fingerprint/binary, BinTimestamps/binary >>.

prepare_timestamps(Timestamps) ->
    lists:foldl(fun prepare_timestamp/2, <<>>, Timestamps).

prepare_timestamp({Timestamp_beg, Timestamp_end}, ResultSoFar) ->
    << ResultSoFar/binary, Timestamp_beg:32, Timestamp_end:32 >>.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Signing
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
request_signature(Service_ID) ->
    gen_server:call(db_serv, {get_signature, Service_ID}).

sign(Service_ID, ScanResults) ->
    Key_info = prepare_key_info(ScanResults),
    SIDBin   = list_to_binary(Service_ID),
    Data = << SIDBin/binary, Key_info/binary >>,
    
    key_sup:sign(Data).
