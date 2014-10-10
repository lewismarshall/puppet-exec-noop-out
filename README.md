puppet-exec-noop-out
====================

A puppet exec type for custom noop output.

Useful for integrating external tools that support an audit or noop mode.

1. Display potential changes in noop mode
1. Will only deploy scripts when run in apply (not noop)
1. Run script in specified user context
1. Supports custom env
1. Will auto transform any parameters representing files to temp paths when run in noop mode

Example:

```Puppet
exec_noop_out { 'audit_script.rb':
  deploy_path   => "${home}/current/utilities/links",
  owner         => $app_user,
  script_name   => "audit_script.rb",
  params        => "${params} apply_changes",
  noop_params   => "${params}",
  files_content => { 'audit_script.rb'          => $audit_script_content,
                     'lib/alib.rb'              => $alib_content,
                     'audit_script.cfg'         => $audit_script_cfg,
                   },
  environment   => ["ORACLE_HOME=${ora_home}",
                    "TNS_ADMIN=${tns_admin}"],
  changes_ret   => 5,
  funcerr_ret   => 10,
}
```

