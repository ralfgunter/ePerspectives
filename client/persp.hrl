%%% Copyright (c) Ralf Gunter. All rights reserved.
%%% The use and distribution terms for this software are covered by the Eclipse
%%% Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
%%% can be found in the file LICENSE at the root of this distribution. By
%%% using this software in any fashion, you are agreeing to be bound by the
%%% terms of this license. You must not remove this notice, or any other, from
%%% this software.

-define(DEFAULT_PORT, 12345).
-define(MAX_PACKET_LEN, 4000).
-define(UDP_OPTIONS, [binary, {active, false}, {reuseaddr, true}]).
-define(TIMEOUT, 8000).
-define(SIG_LEN, 172).

-record(add_server, {ip, port, pubkey}).
-record(del_server, {ip}).
-record(scan_service_id, {service_id}).
-record(scan_results, {results}).
-record(print_results, {output_type}).
