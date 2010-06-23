{application, persp_server,
 [
  {description, "Perspectives server and scanners"},
  {vsn, "0.1"},
  {id, "persp_server"},
  {modules, [persp_udp_listener, persp_http_listener,
             key_sup, persp_scanner_sup, db_server_dets, rescan_server,
             persp_scanner_ssl_sup, persp_scanner_ssh_sup,
             persp_scanner_ssl, persp_scanner_ssh, key_signer,
             persp, persp_scanner]},
  {registered, [udp_listen, http_listen,
                key_serv, scanner_sup, db_serv, rescan_server,
                persp_scanner_ssl_sup, persp_scanner_ssh_sup]},
  {applications, [kernel, stdlib]},
  {mod, {persp_server_app, []}},
  
  {env, [%% Network
         {udp_port,  15217},
         {http_port, 8080},
         {bind_addr, {127,0,0,1}},
         
         %% Database
         {db_files, ["../db/sids", "../db/cache", "../db/signatures"]},
         
         %% Signing
         {private_key, "../keys/private.pem"},
         
         %% HTTP server
         {server_name, "Perspectives HTTP Server"},
         {server_root, "../http_root"},
         {document_root, "../http_root/htdocs"},
         
         %% Scanners (for use by rescan_server)
         {scanner_modules, [persp_scanner_ssl, persp_scanner_ssh]},
         
         %% SSL scanner
         {ssl_timeout, 5000},
         
         %% SSH scanner
         % Although erlang doesn't seem to touch ~/.ssh/known_hosts in my
         % machine, I'm setting it here to somewhere else, just to be on the
         % safe side.
         {ssh_opts, [{user, "perspectives"}, {password, "perspectives"},
                     {user_dir, "../keys"}, {silently_accept_hosts, true},
                     {key_cb, persp_scanner_ssh}]},
         {ssh_timeout, 5000},
         
         %% Rescanning
         % The server updates all the entries in its cache database every
         % rescan_interval miliseconds.
         {rescan_interval, 86400000},
         
         %% Misc
         % If more than max_restart restarts happen in less than max_time
         % seconds, the application is shut down.
         {max_restart, 5},
         {max_time, 60},
         % Default timeout for persp_scanner_sup:handle_scan_results
         {def_timeout, 5000}
        ]}
 ]
}.
