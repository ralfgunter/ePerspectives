%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_http_parser).

-export([prepare_response/2]).

-define(VERSION, "1").


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Preparing the response
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
prepare_response(Service_ID, Results) ->
    Keystamps = lists:map(fun prepare_keystamp/1, Results),
    {EncodedSig, SigAlgorithm, _SigLen} = get_signature(Service_ID),
    SigType = format_signature_type(SigAlgorithm),
    
    SimpleContent =
        {notary_reply,
            [{version, ?VERSION}, {sig_type, SigType}, {sig, EncodedSig}],
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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Signature handling
request_signature(Service_ID) ->
    gen_server:call(db_serv, {get_signature, Service_ID}).

get_signature(Service_ID) ->
    {SigBin, SigAlgorithm, SigLen} = request_signature(Service_ID),
    EncodedSignature = binary_to_list(base64:encode(SigBin)),
    
    {EncodedSignature, SigAlgorithm, SigLen}.

format_signature_type({rsa, md5}) -> "rsa-md5";
format_signature_type({rsa, sha}) -> "rsa-sha".


% TODO: put this in another module
binary_to_readable_string(Bin) ->
    HexList = lists:map(fun(N) -> httpd_util:integer_to_hexlist(N) end,
                        binary_to_list(Bin)),
    
    string:join(HexList, ":").
