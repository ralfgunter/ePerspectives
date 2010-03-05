-module(persp_parser).
-export([parse_messages/1]).

%% Parse individual scan results (with struct/header)
parse_messages(Results_List) ->
	parse_messages(Results_List, []).

parse_messages([], ParsedList) ->
	{ok, ParsedList};

parse_messages([{ok, {Address, _Port, Data}} | Rest], ParsedList) ->
	Header_length = ((lists:nth(7, Data) bsl 8) bxor lists:nth( 8, Data)) + 10,
	Total_length  = ((lists:nth(3, Data) bsl 8) bxor lists:nth( 4, Data)),
	Sig_length    = ((lists:nth(9, Data) bsl 8) bxor lists:nth(10, Data)),
	Data_length = Total_length - Sig_length,
	
	Num_timestamps = ((lists:nth(Header_length + 1, Data) bsl 8) bxor
					   lists:nth(Header_length + 2, Data)),
	Key_len_bytes  = ((lists:nth(Header_length + 3, Data) bsl 8) bxor
					   lists:nth(Header_length + 4, Data)),
	Timestamp_size = 4,	% Each of the two timestamps occupies 4 bytes
	
	Keys_and_timestamps = lists:sublist(Data, (Header_length + 6), (Data_length - Header_length - 5)),
	
	Result = parse_result(Keys_and_timestamps, Num_timestamps, Key_len_bytes, Timestamp_size),
	parse_messages(Rest, [{Address, Result} | ParsedList]).



%% Parse individual scan results (without struct/header)
parse_result(Data, Num_timestamps, Key_length, Timestamp_size) ->
	parse_result(Data, Num_timestamps, Num_timestamps, Key_length, Timestamp_size, []).

parse_result(_Data, 0, _Num_timestamps, _Key_len_bytes, _Timestamp_size, Results) ->
	Results;

parse_result(Data, TimestampsRemaining, Num_timestamps, Key_length, Timestamp_size, Results) ->
	Scan_length = Key_length + (2 * Timestamp_size),
	CurrentData = lists:sublist(Data,
		((Num_timestamps - TimestampsRemaining) * Scan_length) + 1, Scan_length),
	
	Key = lists:sublist(Data, Key_length),
	Timestamp_begin = ((lists:nth(Key_length + 1, CurrentData) bsl 24) bxor
					   (lists:nth(Key_length + 2, CurrentData) bsl 16) bxor
					   (lists:nth(Key_length + 3, CurrentData) bsl  8) bxor
					   (lists:nth(Key_length + 4, CurrentData))),
	Timestamp_end   = ((lists:nth(Key_length + 5, CurrentData) bsl 24) bxor
					   (lists:nth(Key_length + 6, CurrentData) bsl 16) bxor
					   (lists:nth(Key_length + 7, CurrentData) bsl  8) bxor
					   (lists:nth(Key_length + 8, CurrentData))),
	
	parse_result(Data, TimestampsRemaining - 1, Num_timestamps, Key_length,
					Timestamp_size,
					[{Key, Timestamp_begin, Timestamp_end} | Results]).
