%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp).
-export([conf/1, make_sid/3]).

%% Basically, here go some miscellaneous functions that used to be scattered
%% throughout the code.
conf(Param) ->
    case application:get_env(persp_server, Param) of
        {ok, Value} -> Value;
        undefined -> error_logger:error_msg("Missing parameter ~p\n", [Param])
    end.

make_sid(Address, Port, Service_type) ->
    Address ++ ":" ++ integer_to_list(Port) ++ "," ++ Service_type.
