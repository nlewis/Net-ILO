#!perl

use strict;

use Net::ILO;
use Test::More tests => 5;

my $xml_good = qq|
    <?xml version="1.0"?>
    <RIBCL VERSION="2.22">
        <RESPONSE
            STATUS="0x0000"
            MESSAGE='No error'
        />
    </RIBCL>
    <?xml version="1.0"?>
    <RIBCL VERSION="2.22">
        <RESPONSE
            STATUS="0x0000"
            MESSAGE='No error'
        />
    </RIBCL>
    <?xml version="1.0"?>
    <RIBCL VERSION="2.22">
        <RESPONSE
            STATUS="0x0000"
            MESSAGE='No error'
        />
        <GET_GLOBAL_SETTINGS>
            <TEST_ITEM VALUE="30"/>
        </GET_GLOBAL_SETTINGS>
    </RIBCL>
    <?xml version="1.0"?>
    <RIBCL VERSION="2.22">
        <RESPONSE
            STATUS="0x0000"
            MESSAGE='No error'
        />
    <INFORM>This is a really long message. Longer even than the GET_GLOBAL_SETTINGS response. It shouldn't be the stanza picked up. The other one should be. So if you see this, something went wrong.</INFORM>
    </RIBCL>
|;

my $xml_success_with_inform = qq|
    <?xml version="1.0"?>
    <RIBCL VERSION="2.22">
        <RESPONSE
            STATUS="0x0000"
            MESSAGE='No error'
        />
    </RIBCL>
    <?xml version="1.0"?>
    <RIBCL VERSION="2.22">
        <RESPONSE
            STATUS="0x0000"
            MESSAGE='No error'
        />
    <INFORM>Scripting utility should be updated to the latest version.</INFORM>
    </RIBCL>
    <?xml version="1.0"?>
    <RIBCL VERSION="2.22">
        <RESPONSE
            STATUS="0x0000"
            MESSAGE='No error'
        />
    </RIBCL>
|; 

my $xml_bad = qq|
    <?xml version="1.0"?>
    <RIBCL VERSION="2.22">
|;

my $xml_empty = qq||;

my $ilo = Net::ILO->new;

my $parsed_good  = $ilo->_serialize($xml_good);

my $parsed_bad   = $ilo->_serialize($xml_bad);
my $error_bad    = $ilo->error;

my $parsed_empty = $ilo->_serialize($xml_empty);
my $error_empty  = $ilo->error;

my $parsed_success_with_inform = $ilo->_serialize($xml_success_with_inform);

ok( $parsed_good->{GET_GLOBAL_SETTINGS}->{TEST_ITEM}->{VALUE} == 30, 'XML parsed correctly' );
ok( !$parsed_bad,                                                    'Bad XML sent to parser returns false' );
ok( !$parsed_empty,                                                  'Null data sent to parser returns false' );
ok( $error_empty eq 'Error parsing response: no data received',      'Error message set for null data');
ok( $parsed_success_with_inform->{INFORM},                           'When all messages are successful, the longest message is returned'); 
