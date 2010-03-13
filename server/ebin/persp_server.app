{application, persp_server,
 [
  {description, "Perspectives server/scanner"},
  {vsn, "0.1"},
  {id, "persp_server"},
  {modules,      [udp_listener, persp_scanner_fsm]},
  {registered,   [persp_server_sup, udp_listener]},
  {applications, [kernel, stdlib]},
  %%
  %% mod: Specify the module name to start the application, plus args
  %%
  {mod, {persp_server_app, []}},
  {env, []}
 ]
}.
