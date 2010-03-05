-define(DEFAULT_PORT, 12345).
-define(MAX_PACKET_LEN, 4000).
-define(UDP_OPTIONS, [{active, false}, {reuseaddr, true}]).
-define(TIMEOUT, 8000).
-define(SIG_LEN, 172).

-record(add_server, {ip, port, pubkey}).
-record(del_server, {ip}).
-record(scan_service_id, {service_id}).
-record(scan_results, {results}).
