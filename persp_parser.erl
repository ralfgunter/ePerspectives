%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_parser).
-export([parse_messages/1]).

%% Parse individual scan results
parse_messages(Results_List) ->
	parse_server_result(Results_List, []).

% Each server goes through this once
parse_server_result([], ParsedList) ->
	{ok, ParsedList};

parse_server_result([{error, Reason, IP} | Rest], ParsedList) ->
	parse_server_result(Rest, [{error, Reason, IP} | ParsedList]);

parse_server_result([{ok, {Address, _Port, Data}} | Rest], ParsedList) ->
	<<_:16, Total_len:16, _:16, Name_len:16, Sig_len:16, PostHeader/binary>> = Data,
	
	% The notary_header struct occupies 10 bytes; after it is the service id
	% string, which occupies Name_len bytes.
	Header_len = Name_len + 10,
	Data_len   = Total_len - Sig_len - Header_len,
	
	% Strips away the notary_header, service id (SID) and signature info.
	<<_SID:Name_len/bytes, Key_info:Data_len/bytes, _/binary>> = PostHeader,
	
	Result = parse_key_info(Key_info),
	parse_server_result(Rest, [{Address, Result} | ParsedList]).


%% Parse individual keys
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
	<<Num_timestamps:16, Key_len_bytes:16, _:8, Key_info/binary>> = Data,
	TLen = (2 * 4 * Num_timestamps),
	<<Key:Key_len_bytes/bytes, Timestamps:TLen/bytes, Rest/binary>> = Key_info,
	
	ParsedTimestamps = parse_timestamps(Timestamps),
	parse_individual_keys(Rest, [{Key, ParsedTimestamps} | Results]).


%% Parse individual key stamps
parse_timestamps(TimestampsInfo) ->
	parse_individual_timestamps(TimestampsInfo, []).

% Each keystamp goes through this once
parse_individual_timestamps(<<>>, Results) ->
	Results;

parse_individual_timestamps(CurrentTimestampInfo, Results) ->
	<<Begin:32, End:32, NewTimestampInfo/binary>> = CurrentTimestampInfo,
	
	parse_individual_timestamps(NewTimestampInfo, [{Begin, End} | Results]).
