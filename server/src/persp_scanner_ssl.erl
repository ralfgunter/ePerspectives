%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_scanner_ssl).
-behaviour(persp_scanner).

-define(SOCKET_OPTS, [binary, {reuseaddr, true}, {active, false}]).

%% External API
-export([start_link/0]).

%% persp_scanner callbacks
-export([init/1, get_fingerprint/2]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link() ->
    persp_scanner:start_link(?MODULE, []).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% persp_scanner callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init(_Args) -> ok.

get_fingerprint(Address, Port) ->
    case ssl:connect(Address, Port, ?SOCKET_OPTS, persp:conf(ssl_timeout)) of
        {ok, Socket} ->
            PotentialCertificate = ssl:peercert(Socket),
            ssl:close(Socket),
            case PotentialCertificate of
                {ok, Certificate} ->
                    KeyFingerprint = crypto:md5(Certificate),
                    
                    {ok, KeyFingerprint};
                {error, Reason} ->
                    error_logger:error_msg(
                        "Failed to extract certificate from ~p:~p\n~p\n",
                        [Address, Port, Reason]),
                    
                    {error, Reason}
            end;
        {error, Reason} ->
            error_logger:error_msg("Failed to connect to ~p:~p\n~p\n",
                                   [Address, Port, Reason]),
            {error, Reason}
    end.
