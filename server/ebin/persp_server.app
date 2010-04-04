{application, persp_server,
 [
  {description, "Perspectives server/scanner"},
  {vsn, "0.1"},
  {id, "persp_server"},
  {modules,      [udp_listener, persp_scanner_fsm, key_sup, key_signer, db_sup, db_dets, rescan_server, persp_scanner_sup]},
  {registered,   [scanner_sup, udp_listen, key_serv, db_serv, rescan_serv]},
  {applications, [kernel, stdlib]},
  %%
  %% mod: Specify the module name to start the application, plus args
  %%
  {mod, {persp_server_app, []}},
  {env, []}
 ]
}.
