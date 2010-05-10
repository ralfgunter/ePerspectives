%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_interface).

-export([start/0]).
-export([add_server/4, del_server/1]).
-export([scan/3]).
-export([print/0]).
-export([pubkey_pem_to_string/1]).

%% Client startup
start() ->
    gen_server:start_link({local, persp_gs}, persp_gs, [], []).

%% Servers list management
% Server_type defines whether the notary server is UDP- or HTTP-based
add_server(Address, Port, Public_Key, Server_type) ->
    gen_server:call(persp_gs,
                    {add_server, {Address, Port, Public_Key, Server_type}}).

del_server(Address) ->
    gen_server:call(persp_gs, {del_server, Address}).

%% Fetching and printing the results
scan(Address, Port, Service_type) ->
    gen_server:call(persp_gs, {scan, {Address, Port, Service_type}}).

print() ->
    gen_server:call(persp_gs, print).

%% Supporting functions
pubkey_pem_to_string(Filename) ->
    {ok, KeyBin} = file:read_file(Filename),
    
    binary_to_list(KeyBin).
