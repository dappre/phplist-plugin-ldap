# LDAP authentication plugin for phpList
This repository contains an LDAP authentication plugin for phpList.

It is initialy based on an old patch for phplist_auth.inc submitted by bpeabody on [phplist Mantis](https://mantis.phplist.org/view.php?id=9816).
And has been reworked to fit the new approach introduced in v3.2.7 as described in [phplist documentation](https://resources.phplist.com/develop/authentication_plugin).

## Installation
This plugin is intended to be installable from the [Plugin Manager](https://www.phplist.org/manual/ch042_phplist-plugins.xhtml), as it follows the requirements described in the [documentation](https://resources.phplist.com/develop/plugins#phplist_plugins_and_github)

## Configuration
As described in the initial patch, the configuration has to be defined from the main [configuration file](https://resources.phplist.com/system/config).

### Example:
```
$ldap_enabled = 1;
$ldap_url = "ldaps://example.com:636";
$ldap_auth_bind_dn = "cn=readonly,ou=people,dc=example,dc=com";
$ldap_auth_bind_pw = "changeme";
$ldap_all_user_base_dn = "ou=People,dc=example,dc=com";
$ldap_all_user_pattern = "(uid=__LOGIN__)";
$ldap_all_user_uid_attribute = "uid";
$ldap_all_user_is_super = 1;
$ldap_default_privs = array(
      'subscribers' => true,
      'campaigns' => true,
      'statistics' => true,
      'settings' => true
);
$ldap_matching_user_base_dn = "ou=People,dc=example,dc=com";
$ldap_matching_user_pattern = "(&(uid=__LOGIN__)(|(uid=her)(uid=him)))";
$ldap_matching_user_uid_attribute = "uid";
$ldap_except_users = array('admin');
```

## Known issues
- [Manage administartors page is read-only](https://github.com/digital-me/phplist-plugin-ldap/issues/1)
- [Forgot password gets confusing](https://github.com/digital-me/phplist-plugin-ldap/issues/2)

## Todo
- Improve configuration documentation, possibly adding the original example file
- Add support for LDAP groups
- Allow configuration from the plugin, if relevant
- Add [automated test](https://resources.phplist.com/develop/plugin_automated_testing) via Travis CI
