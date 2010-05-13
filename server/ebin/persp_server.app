{application, persp_server,
 [
  {description, "Perspectives server/scanner"},
  {vsn, "0.1"},
  {id, "persp_server"},
  {modules,      [persp_udp_listener, persp_http_listener, persp_scanner_ssl, persp_scanner_sup, key_sup, key_signer, db_server_dets, rescan_server]},
  {registered,   [udp_listen, http_listen, scanner_sup, db_serv, key_serv, rescan_server]},
  {applications, [kernel, stdlib]},
  %%
  %% mod: Specify the module name to start the application, plus args
  %%
  {mod, {persp_server_app, []}},
  {env, []}
 ]
}.
