%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(key_signer).

-include_lib("public_key/include/public_key.hrl").

%% External API
-export([start_link/1]).

%% Internal API
-export([handle_request/1]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(KeyTuple) ->
    Pid = spawn_link(?MODULE, handle_request, [KeyTuple]),
    
    {ok, Pid}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
handle_request(KeyTuple) ->
    receive
        {sign, From, Data, DigestType} ->
            Signature = sign(Data, DigestType, KeyTuple),
            From ! {ok, Signature}
    end.

sign(Data, DigestType, {Mp_priv_exp, Mp_pub_exp, Mp_mod}) ->
    Mp_data = << (byte_size(Data)):32/integer-big, Data/binary >>,
    
    crypto:rsa_sign(DigestType, Mp_data, [Mp_pub_exp, Mp_mod, Mp_priv_exp]).
