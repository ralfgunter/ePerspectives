{application, persp_server,
 [
  {description, "Perspectives server/scanner"},
  {vsn, "0.1"},
  {id, "persp_server"},
  {modules,      [persp_udp_listener, persp_http_listener, persp_scanner_ssl, persp_scanner_sup, key_sup, key_signer, db_server_dets, rescan_server, persp]},
  {registered,   [udp_listen, http_listen, scanner_sup, db_serv, key_serv, rescan_server]},
  {applications, [kernel, stdlib]},
  {mod, {persp_server_app, []}},
  
  {env, [%% Network
         {udp_port,  15217},
         {http_port, 8080},
         {bind_addr, {127,0,0,1}},
         
         %% Scanning
         %% TODO: once a proper modularization system is in place, this should
         %%       go to its own config file.
         {scanner_modules, [persp_scanner_ssl]},
         
         %% Database
         {db_files, ["../db/sids", "../db/cache", "../db/signatures"]},
         
         %% Signing
         {private_key, "../keys/private.pem"},
         
         %% HTTP server
         {server_name, "Perspectives HTTP Server"},
         {server_root, "../http_root"},
         {document_root, "../http_root/htdocs"},
         
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
