#!/bin/sh
# Wrapper do basic_ldap_auth falso (tests/php/fake_basic_ldap_auth.php)
exec php "$(dirname "$0")/fake_basic_ldap_auth.php" "$@"
