%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_scanner_ssh).
-behaviour(persp_scanner).

%% External API
-export([start_link/0]).

%% persp_scanner callbacks
-export([init/1, get_fingerprint/2]).

%% key_cb callbacks
-export([add_host_key/3, lookup_host_key/3,
         private_host_rsa_key/2, private_host_dsa_key/2]).


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
    case ssh:connect(Address, Port, [{replyto, self()} | persp:conf(ssh_opts)],
                     persp:conf(ssh_timeout)) of
        {ok, PID} ->    % either sheer luck or a smarty-pants admin got us in
            ssh:close(PID),
            receive
                {key_fingerprint, Fingerprint} -> {ok, Fingerprint}
            end;
        % TODO: it would be nice not to have to gamble like this
        {error,"Unable to connect using the available authentication methods"}->
            receive
                {key_fingerprint, Fingerprint} -> {ok, Fingerprint}
                after persp:conf(ssh_timeout) -> {error, receive_timeout}
            end;
        {error, Reason} ->
            error_logger:error_msg("Unknown error at ~p:~p\n~s\n",
                                   [Address, Port, Reason]),
            {error, Reason}
    end.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% key_cb - handling the public key sent by the SSH daemon (see ssh:connect)
add_host_key(_Host, Key, Opts) ->
    KeyFingerprint = persp_crypto:key_fingerprint(Key),
    {_replyto, ReplyTo} = lists:keyfind(replyto, 1, Opts),
    ReplyTo ! {key_fingerprint, KeyFingerprint}.

private_host_rsa_key(_, _) -> ok.
private_host_dsa_key(_, _) -> ok.
lookup_host_key(_, _, _) -> {error, not_found}.
