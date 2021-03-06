%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_udp_parser).

-export([parse_server_result/1]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
parse_server_result({error, Reason, IP}) ->
    {error, Reason, IP};

parse_server_result({Address, _Port, PKey, Data}) ->
    <<_:16, Total_len:16, _:16, Name_len:16, Sig_len:16, PostHeader/binary>> = Data,
    
    % The notary_header struct occupies 10 bytes; after it is the service id
    % string, which occupies Name_len bytes.
    Header_len = Name_len + 10,
    Data_len   = Total_len - Sig_len - Header_len,
    
    % Strips away the notary_header, service id (SID) and signature info.
    << SID:Name_len/bytes, Key_info:Data_len/bytes, Sig/binary >> = PostHeader,
    
    % Verifies the signature
    SignedData = << SID/binary, Key_info/binary >>,
    case persp_crypto:verify_rsa_signature(SignedData, Sig, PKey) of
        true ->
            {Address, parse_key_info(Key_info)};
        false ->
            {error, signature_check_failed, Address}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Parsing keys
parse_key_info(Key_info) ->
    parse_individual_keys(Key_info, []).

% Each key goes through this once
parse_individual_keys(<<>>, Results) ->
    Results;

parse_individual_keys(Data, Results) ->
    %% Each key_info occupies:
    % - 5 bytes for the ssh_key_info struct;
    %   - num_timestamps: 2 bytes;
    %   - key_len_bytes:  2 bytes;
    %   - key_type:       1 byte;
    % - key_len_bytes bytes for the key itself;
    % - 2 (start/end pair) * 4 * (number of timestamps) bytes.
    << Num_timestamps:16, Key_len_bytes:16, _:8, Key_info/binary >> = Data,
    TLen = (2 * 4 * Num_timestamps),
    <<Key:Key_len_bytes/bytes, Timestamps:TLen/bytes, Rest/binary>> = Key_info,
    
    ParsedTimestamps = parse_timestamps(Timestamps),
    parse_individual_keys(Rest, [{Key, ParsedTimestamps} | Results]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Parsing timestamps
parse_timestamps(TimestampsInfo) ->
    parse_individual_timestamps(TimestampsInfo, []).

% Each keystamp goes through this once
parse_individual_timestamps(<<>>, Results) ->
    Results;

parse_individual_timestamps(CurrentTimestampInfo, Results) ->
    << Begin:32, End:32, NewTimestampInfo/binary >> = CurrentTimestampInfo,
    
    parse_individual_timestamps(NewTimestampInfo, [{Begin, End} | Results]).
