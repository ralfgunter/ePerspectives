%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_http_parser).

-include_lib("xmerl/include/xmerl.hrl").

-export([parse_server_result/1]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
parse_server_result({error, Reason, IP}) ->
    {error, Reason, IP};

parse_server_result({Address, _Port, PKey, Data}) ->
    {XML, _} = xmerl_scan:string(Data),
    Sig     = (hd(xmerl_xpath:string("@sig",      XML)))#xmlAttribute.value,
    SigType = (hd(xmerl_xpath:string("@sig_type", XML)))#xmlAttribute.value,
    
    Keys = xmerl_xpath:string("/notary_reply/key", XML),
    
    % TODO: check signature
    {Address, parse_keys(Keys)}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Parsing keys
parse_keys(KeyList) ->
    parse_individual_keys(KeyList, []).

parse_individual_keys([], Results) ->
    Results;

parse_individual_keys([Key | Rest], Results) ->
    Fingerprint = (hd(xmerl_xpath:string("@fp", Key)))#xmlAttribute.value,
    Timestamps = xmerl_xpath:string("/key/timestamp", Key),
    ParsedTimestamps = parse_timestamps(Timestamps),
    
    parse_individual_keys(Rest, [{Fingerprint, ParsedTimestamps} | Results]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Parsing timestamps
parse_timestamps(TimestampsInfo) ->
    parse_individual_timestamps(TimestampsInfo, []).

parse_individual_timestamps([], Results) ->
    Results;

parse_individual_timestamps([Timestamp | Rest], Results) ->
    Begin = (hd(xmerl_xpath:string("@start", Timestamp)))#xmlAttribute.value,
    End   = (hd(xmerl_xpath:string("@end",   Timestamp)))#xmlAttribute.value,
    
    parse_individual_timestamps(Rest, [{Begin, End} | Results]).
