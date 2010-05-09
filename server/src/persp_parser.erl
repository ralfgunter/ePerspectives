%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_parser).

-define(SIG_LEN, 172).

-export([parse_scan_data/1, parse_sid_list/1]).
-export([prepare_response/2]).

-record(scan_data, {socket, address, port, data}).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Parsing
parse_scan_data(ScanData) ->
	<< _:80, SIDBin/binary >> = ScanData#scan_data.data,
	
	parse_sid_bin(SIDBin).

parse_sid_list(SIDList) ->
	% Here the last element of the list is a NULL, which must be removed in
	% this module, because all other modules using it assume it's not there.
	[Address, StrPort, [Service_type | _NULL]] = string:tokens(SIDList, ":,"),
	
	{Address, list_to_integer(StrPort), [Service_type]}.

parse_sid_bin(SIDBin) ->
	SIDList = binary_to_list(SIDBin),
	
	parse_sid_list(SIDList).

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
	Lambda = fun(CurrentTimestamp, ResultSoFar) ->
		{Timestamp_beg, Timestamp_end} = CurrentTimestamp,
		
		<< ResultSoFar/binary, Timestamp_beg:32, Timestamp_end:32 >>
	end,
	
	lists:foldl(Lambda, <<>>, Timestamps).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Signing
sign(Key_info, SIDBin) ->
	Data = << SIDBin/binary, Key_info/binary >>,
	Signature = sign_data(Data),
	
	Signature.

sign_data(Data) ->
	key_sup:sign(Data).
