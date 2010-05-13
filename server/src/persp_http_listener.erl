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

-define(SERVER_NAME,   "Perspectives HTTP Server").
-define(SERVER_ROOT,   "../http_root").
-define(DOCUMENT_ROOT, "../http_root/htdocs").

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
              {server_root, ?SERVER_ROOT}, {document_root, ?DOCUMENT_ROOT},
              {server_name, ?SERVER_NAME},
              {modules, [persp_http_listener]}],
    
    inets:start(),      % There must be a better way to do this
    
    inets:start(httpd, Config).

terminate(_Reason, HTTPd_Pid) ->
    inets:stop(httpd, HTTPd_Pid).

code_change(_OldVersion, HTTPd_Pid, _Extra) ->
    {ok, HTTPd_Pid}.

handle_call(Request, _From, HTTPd_Pid) ->
    {stop, {unknown_call, Request}, HTTPd_Pid}.

handle_cast(_Msg, HTTPd_Pid) ->
    {noreply, HTTPd_Pid}.

handle_info(_Info, HTTPd_Pid) ->
    {noreply, HTTPd_Pid}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%
%% Internal API
%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% TODO: we're still not checking for possibly malformed Addresses, Ports and
%       SvTypes; do something about it.
parse_request(String) ->
    case string:tokens(String, "&=") of
        ["/?host", Address, "port", Port, "service_type", SvType, "HTTP/1.1"] ->
            {ok, {Address, list_to_integer(Port), SvType}};
        _MalformedRequest ->
            error_logger:error_msg("Malformed request", String),
            {error, String}
    end.

%% Callback used when someone makes a scan request to the httpd
do(ModData) ->
    case parse_request(ModData#mod.request_uri) of
        {ok, ParsedRequest} ->
            Body = persp_scanner_sup:handle_request(http, ParsedRequest),
            StatusCode = 200;
        {error, _MalformedRequest} ->
            Body = "Malformed request",
            StatusCode = 400
    end,
    
    {break, [{response, {StatusCode, Body}}]}.
