#!perl

use strict;

use Net::ILO;
use Test::More tests => 3;

# TODO: mock IO::Socket::SSL object for better testing

my $ilo = Net::ILO->new;

my $connection;

eval { $connection = $ilo->_connect; };

ok( $@ =~ "Can't connect: address not set", 'Connecting without address throws exception' );

$ilo->address('127.0.0.1');
$ilo->port(undef);

eval { $connection = $ilo->_connect; };

ok( $@ =~ "Can't connect: port not set",    'Connecting without port throws exception' );

$ilo->{_client} = 'Fake connection';

$connection = $ilo->_connect;

ok( $connection eq 'Fake connection',       '_connect returns cached connection' );

# so DESTROY doesn't try to disconnect during cleanup
undef $ilo->{_client};
