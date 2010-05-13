%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_http_parser).

-export([parse_sid_list/1]).
-export([prepare_response/2]).

%% TODO: make these customizable
-define(SIG_TYPE, "rsa-md5").
-define(SIG_LEN,        172).
-define(VERSION,        "1").


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Parsing
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% TODO: this might be unnecessary if the database is structured differently;
%       investigate.
parse_sid_list(SIDList) ->
    % Here the last element of Service_type is a NULL, which must be removed in
    % this module because all other modules using it assume it's not there.
    [Address, StrPort, [Service_type, 0]] = string:tokens(SIDList, ":,"),
    
    {Address, list_to_integer(StrPort), [Service_type]}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Preparing the response
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
prepare_response(Service_ID, Results) ->
    Keystamps = lists:map(fun prepare_keystamp/1, Results),
    Signature = get_udp_signature(Service_ID, Results),
    
    SimpleContent =
        {notary_reply,
            [{version, ?VERSION}, {sig_type, ?SIG_TYPE}, {sig, Signature}],
            Keystamps},
    
    lists:flatten(xmerl:export_simple([SimpleContent], xmerl_xml)).

prepare_keystamp({BinaryFingerprint, Timestamps}) ->
    Timestamp_entries = lists:map(fun prepare_timestamps/1, Timestamps),
    Fingerprint = binary_to_readable_string(BinaryFingerprint),
    
    % TODO: make "ssl" scanner-dependant
    {key,
        [{type, "ssl"}, {fp, Fingerprint}],
        Timestamp_entries}.

prepare_timestamps({Start, End}) ->
    {timestamp,
        [{start,               integer_to_list(Start)},
         {list_to_atom("end"), integer_to_list(End)}],  % TODO: this is a
        []}.                                            % horrible hack; fix it


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
get_udp_signature(Service_ID, Results) ->
    UDPResponse = persp_udp_parser:prepare_response(Service_ID, Results),
    persp_udp_parser:get_signature(UDPResponse).

% TODO: put this in another module
binary_to_readable_string(Bin) ->
    HexList = lists:map(fun(N) -> httpd_util:integer_to_hexlist(N) end,
                        binary_to_list(Bin)),
    
    string:join(HexList, ":").
