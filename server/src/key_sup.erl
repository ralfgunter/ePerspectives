%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(key_sup).
-behaviour(supervisor).

-include_lib("public_key/include/public_key.hrl").

%% External API
-export([sign/1]).

%% Supervisor behaviour callbacks
-export([start_link/1]).
-export([init/1]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
sign(Data) ->
    {ok, Pid} = supervisor:start_child(?MODULE, []),
    Pid ! {sign, self(), Data, md5},
    
    receive
        {ok, Signature} -> Signature
    end.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Supervisor behaviour callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(PrivateKeyFilepath) ->
    KeyTuple = prepare_key(PrivateKeyFilepath),
    supervisor:start_link({local, ?MODULE}, ?MODULE, KeyTuple).

init(KeyTuple) ->
    {ok,
        { {simple_one_for_one, persp:conf(max_restart), persp:conf(max_time)},
          [{ signer,
             {key_signer, start_link, [KeyTuple]},
             temporary, brutal_kill, worker, []
          }]
        }
    }.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
process_key_file(PrivKeyFilepath) ->
    %% Private key parsing.
    % TODO: do something about password-protected private keys
    {ok, [KeyInfo]}  = public_key:pem_to_der(PrivKeyFilepath),
    {ok, PrivateKey} = public_key:decode_private_key(KeyInfo),
    
    PrivateKey.

privkey_to_mpint(PrivKey) ->
    Private_Exponent = PrivKey#'RSAPrivateKey'.privateExponent,
    Public_Exponent  = PrivKey#'RSAPrivateKey'.publicExponent,
    Modulus          = PrivKey#'RSAPrivateKey'.modulus,
    
    Mp_priv_exp = crypto:mpint(Private_Exponent),
    Mp_pub_exp  = crypto:mpint(Public_Exponent),
    Mp_mod      = crypto:mpint(Modulus),
    
    {Mp_priv_exp, Mp_pub_exp, Mp_mod}.

prepare_key(PrivKeyFilepath) ->
    PrivateKey = process_key_file(PrivKeyFilepath),
    KeyTuple   = privkey_to_mpint(PrivateKey),
    
    KeyTuple.
