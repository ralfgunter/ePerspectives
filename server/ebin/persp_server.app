{application, persp_server,
 [
  {description, "Perspectives server/scanner"},
  {vsn, "0.1"},
  {id, "persp_server"},
  {modules,      [udp_listener, persp_scanner_fsm, persp_scanner_sup, key_sup, key_signer, db_server_dets]},
  {registered,   [udp_listen, scanner_sup, db_serv, key_serv]},
  {applications, [kernel, stdlib]},
  %%
  %% mod: Specify the module name to start the application, plus args
  %%
  {mod, {persp_server_app, []}},
  {env, []}
 ]
}.
