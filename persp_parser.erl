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
	Header_length = ((lists:nth(7, Data) bsl 8) bxor lists:nth( 8, Data)) + 10,
	Total_length  = ((lists:nth(3, Data) bsl 8) bxor lists:nth( 4, Data)),
	Sig_length    = ((lists:nth(9, Data) bsl 8) bxor lists:nth(10, Data)),
	Data_length = Total_length - Sig_length - Header_length,
	
	% Strips away the notary_header and signature info
	Key_info = lists:sublist(Data, Header_length + 1, Data_length),
	
	Result = parse_key_info(Key_info),
	parse_server_result(Rest, [{Address, Result} | ParsedList]).


%% Parse individual keys
parse_key_info(Key_info) ->
	parse_individual_keys(Key_info, []).

% Each key goes through this once
parse_individual_keys([], Results) ->
	Results;

parse_individual_keys(Data, Results) ->
	Num_timestamps = ((lists:nth(1, Data) bsl 8) bxor lists:nth(2, Data)),
	Key_len_bytes  = ((lists:nth(3, Data) bsl 8) bxor lists:nth(4, Data)),
	
	%% Each key_info occupies:
	% - 5 bytes for the ssh_key_info struct;
	% - key_len_bytes bytes for the key itself;
	% - 2 * 4 (uint32_t) * (number of timestamps) bytes.
	% + 1 is because of erlang's 1-based indexing
	Key = lists:sublist(Data, 5 + 1, Key_len_bytes),
	
	TimestampsInfo = lists:sublist(Data, 5 + Key_len_bytes + 1,
													(2 * 4 * Num_timestamps)),
	ParsedTimestamps = parse_timestamps(TimestampsInfo),
	
	Rest_of_Data = lists:nthtail((5 + Key_len_bytes + (2 * 4 * Num_timestamps)),
								 Data),
	
	parse_individual_keys(Rest_of_Data, [{Key, ParsedTimestamps} | Results]).


%% Parse individual key stamps
parse_timestamps(TimestampsInfo) ->
	parse_individual_timestamps(TimestampsInfo, []).

% Each keystamp goes through this once
parse_individual_timestamps([], Results) ->
	Results;

parse_individual_timestamps(CurrentTimestampInfo, Results) ->
	Timestamp_begin = ((lists:nth(1, CurrentTimestampInfo) bsl 24) bxor
					   (lists:nth(2, CurrentTimestampInfo) bsl 16) bxor
					   (lists:nth(3, CurrentTimestampInfo) bsl  8) bxor
					   (lists:nth(4, CurrentTimestampInfo))),
	Timestamp_end   = ((lists:nth(5, CurrentTimestampInfo) bsl 24) bxor
					   (lists:nth(6, CurrentTimestampInfo) bsl 16) bxor
					   (lists:nth(7, CurrentTimestampInfo) bsl  8) bxor
					   (lists:nth(8, CurrentTimestampInfo))),
	
	NewTimestampInfo = lists:nthtail(8, CurrentTimestampInfo),
	
	parse_individual_timestamps(NewTimestampInfo,
								[{Timestamp_begin, Timestamp_end} | Results]).
