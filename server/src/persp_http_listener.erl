%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-module(persp_http_listener).
-behaviour(gen_server).

%% External API
-export([start_link/2]).

%% gen_server callbacks
-export([init/1, terminate/2]).
-export([handle_call/3, handle_cast/2, handle_info/2]).
-export([code_change/3]).

% Module API
-export([do/1]).

% From $ERLANG_SRC_ROOT/lib/inets/src/http_server/httpd.hrl
-record(mod,{init_data,
             data=[],
             socket_type=ip_comm,
             socket,
             config_db,
             method,
             absolute_uri=[],
             request_uri,
             http_version,
             request_line,
             parsed_header=[],
             entity_body,
             connection}).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% External API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
start_link(BindAddress, Port) when is_integer(Port) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, {BindAddress, Port}, []).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% gen_server callbacks
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
init({BindAddress, Port}) ->
    Config = [{port, Port}, {bind_address, BindAddress},
              {server_name,   persp:conf(server_name)},
              {server_root,   persp:conf(server_root)},
              {document_root, persp:conf(document_root)},
              {modules, [persp_http_listener]}],
    
    inets:start(),
    inets:start(httpd, Config).

terminate(_Reason, HTTPd_Pid) ->
    inets:stop(httpd, HTTPd_Pid).

handle_call(Request, _From, HTTPd_Pid) ->
    {stop, {unknown_call, Request}, HTTPd_Pid}.

handle_cast(_Msg, HTTPd_Pid) -> {noreply, HTTPd_Pid}.
handle_info(_Info, HTTPd_Pid) -> {noreply, HTTPd_Pid}.
code_change(_OldVersion, HTTPd_Pid, _Extra) -> {ok, HTTPd_Pid}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% TODO: we're still not checking for possibly malformed Addresses, Ports and
%       SvTypes; do something about it.
% TODO: the order of the 'keywords' (host, port, service_type, etc) should not
%       matter; write a better parser.
parse_request(String) ->
    case string:tokens(String, "&=") of
        ["/?host", Address, "port", Port, "service_type", SvType, "HTTP/1.1"] ->
            {ok, {Address, list_to_integer(Port), SvType}};
        _MalformedRequest ->
            {error, String}
    end.

%% Callback used when someone makes a scan request to the httpd
do(ModData) ->
    case parse_request(ModData#mod.request_uri) of
        {ok, ParsedRequest} ->
            case persp_scanner_sup:handle_request(http, ParsedRequest) of
                {ok, ParsedResults} ->
                    Body = ParsedResults,
                    StatusCode = 200;
                {error, _Reason} ->
                    Body = "Scan error",
                    StatusCode = 500;
                timeout ->
                    Body = "Scan timeout",
                    StatusCode = 500
            end;
        {error, MalformedRequest} ->
            {SrcPort, SrcIP} = httpd_socket:peername(ModData#mod.socket_type,
                                                     ModData#mod.socket),
            error_logger:error_msg("Malformed request from ~s:~p\n~p\n",
                                   [SrcIP, SrcPort, MalformedRequest]),
            Body = "Malformed request",
            StatusCode = 400
    end,
    
    {break, [{response, {StatusCode, Body}}]}.
