#!perl

use strict;

use Data::Dumper;
use Net::ILO;
use Test::More tests => 10;

my $ilo_defaults = Net::ILO->new;

ok( !$ilo_defaults->address,    'Default address is null' );
ok( !$ilo_defaults->username,   'Default username is null' );
ok( !$ilo_defaults->password,   'Default password is null' );
ok( $ilo_defaults->_debug == 0, 'Default debug level is 0' ); 
ok( $ilo_defaults->port == 443, 'Default port is 443' );

my $ilo = Net::ILO->new({
    address  => '127.0.0.1',
    username => 'Administrator',
    password => '12345678',
    debug    => 2,
    port     => 2381,
});

ok( $ilo->address eq '127.0.0.1',       'Specifying address in constructor' );
ok( $ilo->username eq 'Administrator',  'Specifying username in constructor' );
ok( $ilo->password eq '12345678',       'Specifying password in constructor' );
ok( $ilo->_debug == 2,                  'Specifying debug level in constructor' );
ok( $ilo->port == 2381,                 'Specifying alternate HTTPS port in constructor' );

