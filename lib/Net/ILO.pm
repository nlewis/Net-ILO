package Net::ILO;

use strict;
use warnings;

use Carp;
use Data::Dumper;
use English qw(-no_match_vars);
use IO::Socket::SSL;
use XML::Simple;
use Scalar::Util qw( reftype );

our $VERSION = '0.54_005';


my $METHOD_UNSUPPORTED = 'Method not supported by this iLO version';


# {{{ address
#
sub address {

    my $self = shift;

    if (@_) {
        $self->{address} = shift;
    }

    return $self->{address};

} # }}}

# {{{ add_user
#
sub add_user {

    my $self = shift;

    if (@_) {

        my $arg_ref = shift;

        my $user_name     = $arg_ref->{name}     or croak 'name required';
        my $user_login    = $arg_ref->{username} or croak 'username required';
        my $user_password = $arg_ref->{password} or croak 'password required';

        my $user_admin          = $arg_ref->{admin}                    || 'No';
        my $user_can_remote     = $arg_ref->{remote_console_privilege} || 'No';
        my $user_can_reset      = $arg_ref->{reset_privilege}          || 'No';
        my $user_can_virtual    = $arg_ref->{virtual_media_privilege}  || 'No';
        my $user_can_config     = $arg_ref->{config_ilo_privilege}     || 'No';
        my $user_can_view_logs  = $arg_ref->{view_logs_privilege}      || 'No';
        my $user_can_clear_logs = $arg_ref->{clear_logs_privilege}     || 'No';
        my $user_can_update     = $arg_ref->{update_ilo_privilege}     || 'No';

        my $ilo_command = qq|
            <USER_INFO MODE="write">
            <ADD_USER USER_NAME="$user_name" USER_LOGIN="$user_login" PASSWORD="$user_password">
            <ADMIN_PRIV value="$user_admin"/>
            <REMOTE_CONS_PRIV value="$user_can_remote"/>
            <RESET_SERVER_PRIV value="$user_can_reset"/>
            <VIRTUAL_MEDIA_PRIV value="$user_can_virtual"/>
            <CONFIG_ILO_PRIV value="$user_can_config"/>
            <VIEW_LOGS_PRIV value="$user_can_view_logs"/>
            <CLEAR_LOGS_PRIV value="$user_can_clear_logs"/>
            <UPDATE_ILO_PRIV value="$user_can_update"/>
            </ADD_USER>
            </USER_INFO>
        |;

        $ilo_command    = $self->_wrap($ilo_command);
        my $response    = $self->_send($ilo_command)    or return;
        my $xml         = $self->_serialize($response)  or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

    }
    else {

        croak 'add_user() requires parameters';

    }

    return 1;

} # }}}

# {{{ biosdate
#
sub biosdate {

    my $self = shift;

    if (!$self->{biosdate}) {
        $self->_populate_host_data or return;
    }

    return $self->{biosdate};

} # }}}

# {{{ cpus
#
sub cpus {

    my $self = shift;

    if (!$self->{cpus}) {
        $self->_populate_host_data or return;
    }

    return $self->{cpus};

} # }}}

# {{{ del_user
#
sub del_user {

    my $self = shift;

    if (@_) {

        my $user_login = shift;

        my $ilo_command = qq|
            <USER_INFO MODE="write">
            <DELETE_USER USER_LOGIN="$user_login"/>
            </USER_INFO>
        |;

        $ilo_command    = $self->_wrap($ilo_command);
        my $response    = $self->_send($ilo_command)    or return;
        my $xml         = $self->_serialize($response)  or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

    }
    else {

        croak 'del_user() requires the username to delete';

    }

    return 1;

} # }}}

# {{{ dhcp_enabled
#
sub dhcp_enabled {

    my $self = shift;

    if (!$self->{dhcp_enable}) {
        $self->_populate_network_settings or return;
    }

    return $self->{dhcp_enable};

} # }}}

# {{{ dhcp_dns_server
#
sub dhcp_dns_server {
    my $self = shift;

    if (not defined $self->{dhcp_dns_server}) {
        $self->_populate_network_settings or return
    }

    return $self->{dhcp_dns_server}

} # }}}

# {{{ dhcp_gateway
#
sub dhcp_gateway {
    my $self = shift;

    if (not defined $self->{dhcp_gateway}) {
        $self->_populate_network_settings or return
    }

    return $self->{dhcp_gateway}

} # }}}

# {{{ dhcp_sntp_settings
#
sub dhcp_sntp_settings {
    my $self = shift;

    if (not defined $self->{dhcp_sntp_settings}) {
        $self->_populate_network_settings or return
    }

    return $self->{dhcp_sntp_settings}

} # }}}

# {{{ domain_name
#
sub domain_name {

    my $self = shift;

    if (!$self->{domain_name}) {
        $self->_populate_network_settings or return;
    }

    return $self->{domain_name};

} # }}}

# {{{ error
#
sub error {

    my $self = shift;

    if (@_) {
        $self->{error} = shift;
    }

    return $self->{error};

} # }}}

# {{{ fans
#
sub fans {

    my $self = shift;

    if (!$self->{fans}) {
        $self->_populate_embedded_health or return;
    }

    return $self->{fans};

} # }}}

# {{{ backplanes 
#
sub backplanes {

   my $self = shift;

   if (!$self->{backplanes}) {
       $self->_populate_embedded_health or return;
   }

   if ($self->{backplanes}) {
       return $self->{backplanes};
   }
   else {
       $self->error($METHOD_UNSUPPORTED);
       return;
   }

} # }}}

sub controllers {

   my $self = shift;

   if (!$self->{controllers}) {
       $self->_populate_embedded_health or return;
   }

   if ($self->{controllers}) {
       return $self->{controllers};
   }
   else {
       $self->error($METHOD_UNSUPPORTED);
       return;
   }

}


# {{{ fw_date
#
sub fw_date {

    my $self = shift;

    if (!$self->{fw_date}) {
        $self->_populate_fw_version or return;
    }

    return $self->{fw_date};

} # }}}

# {{{ fw_type
#
sub fw_type {

    my $self = shift;

    if (!$self->{fw_type}) {
        $self->_populate_fw_version or return;
    }

    return $self->{fw_type};

} # }}}

# {{{ fw_version
#
sub fw_version {

    my $self = shift;

    if (!$self->{fw_version}) {
        $self->_populate_fw_version or return;
    }

    return $self->{fw_version};

} # }}}

# {{{ gateway 
#
sub gateway {

    my $self = shift;

    if (!$self->{gateway_ip_address}) {
        $self->_populate_network_settings or return;
    }

    return $self->{gateway_ip_address};

} # }}}

# {{{ get_user
#
sub get_user {

    my $self = shift;

    croak 'get_user() requires the username' unless @_;

    my $user_login = shift;

    # build the iLO command
    my $ilo_command = qq|
        <USER_INFO MODE="write">
        <GET_USER USER_LOGIN="$user_login"/>
        </USER_INFO>
    |;

    # send the command, read the response
    $ilo_command    = $self->_wrap($ilo_command);
    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if (my $errmsg = _check_errors($xml)) {
        $self->error($errmsg);
        return
    }

    my %user_info = (
        name                        => $xml->{GET_USER}{USER_NAME},
        username                    => $xml->{GET_USER}{USER_LOGIN},
        admin                       => $xml->{GET_USER}{ADMIN_PRIV},
        remote_console_privilege    => $xml->{GET_USER}{REMOTE_CONS_PRIV},
        reset_privilege             => $xml->{GET_USER}{RESET_SERVER_PRIV},
        virtual_media_privilege     => $xml->{GET_USER}{VIRTUAL_MEDIA_PRIV},
        config_ilo_privilege        => $xml->{GET_USER}{CONFIG_ILO_PRIV},
    );

    return \%user_info

} # }}}

# {{{ get_all_users 
#
sub get_all_users {

    my $self = shift;

    if (!$self->{all_users}) {
        $self->_populate_all_users or return;
    }

    return wantarray ? @{$self->{all_users}} : $self->{all_users};

} # }}}

# {{{ get_iml_log 
#
sub get_iml_log {

    my $self = shift;

    if (!$self->{iml_log}) {
        $self->_populate_iml_log or return;
    }

    return $self->{iml_log};

} # }}}

# {{{ get_ilo_log 
#
sub get_ilo_log {

    my $self = shift;

    if (!$self->{ilo_log}) {
        $self->_populate_ilo_log or return;
    }

    return $self->{ilo_log};

} # }}}

# {{{ get_oa_info 
#
sub get_oa_info {

    my $self = shift;

    if (!$self->{oa_info}) {
        $self->_populate_oa_info or return;
    }

    return $self->{oa_info};

} # }}}

# {{{ hostname 
#
sub hostname {

    my $self = shift;

    if (!$self->{dns_name}) {
        $self->_populate_network_settings or return;
    }

    return $self->{dns_name};

} # }}}

# {{{ http_port
#
sub http_port {

    my $self = shift;

    if (@_) {

        my $http_port = shift;

        _port_is_valid($http_port) or croak "HTTP port must be an integer between 0 and 65535";

        my $ilo_command = qq|
            <RIB_INFO MODE="write">
            <MOD_GLOBAL_SETTINGS>
                <HTTP_PORT value="$http_port"/>
            </MOD_GLOBAL_SETTINGS>
            </RIB_INFO>
        |;

        $ilo_command    = $self->_wrap($ilo_command);
        my $response    = $self->_send($ilo_command)    or return;
        my $xml         = $self->_serialize($response)  or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

        $self->{http_port} = $http_port;

    }

    if (!$self->{http_port}) {
        $self->_populate_global_settings or return;
    }

    return $self->{http_port};

} # }}}

# {{{ https_port 
#
sub https_port {

    my $self = shift;

    if (@_) {

        my $https_port = shift;

        _port_is_valid($https_port) or croak "HTTPS port must be an integer between 0 and 65535";

        my $ilo_command = qq|
            <RIB_INFO MODE="write">
            <MOD_GLOBAL_SETTINGS>
                <HTTPS_PORT value="$https_port"/> 
            </MOD_GLOBAL_SETTINGS>
            </RIB_INFO>
        |;

        $ilo_command    = $self->_wrap($ilo_command);
        my $response    = $self->_send($ilo_command)    or return;
        my $xml         = $self->_serialize($response)  or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

        $self->{https_port} = $https_port;

    }

    if (!$self->{https_port}) {
        $self->_populate_global_settings or return;
    }

    return $self->{https_port};

} # }}}

# {{{ ip_address 
#
sub ip_address {

    my $self = shift;

    if (!$self->{ip_address}) {
        $self->_populate_network_settings or return;
    }

    return $self->{ip_address};

} # }}}

# {{{ license 
#
sub license {

    my $self = shift;

    if (@_) {

        my $license_key = shift;

        my $ilo_command = qq|
            <RIB_INFO MODE="write">
            <LICENSE>
                <ACTIVATE KEY="$license_key"/>
            </LICENSE> 
            </RIB_INFO>
        |;

        $ilo_command    = $self->_wrap($ilo_command);
        my $response    = $self->_send($ilo_command)    or return;
        my $xml         = $self->_serialize($response)  or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

    }
    else {

        croak 'license() requires the license key as a paramater';

    }

    return 1;

} # }}}

# {{{ mac01 
#
sub mac01 {

    my $self = shift;

    if (!$self->{mac01}) {
        $self->_populate_host_data or return;
    }

    if ($self->{mac01}) {
        return $self->{mac01};
    }
    else {
        $self->error($METHOD_UNSUPPORTED);
        return;
    }

} # }}}

# {{{ mac02 
#
sub mac02 {

    my $self = shift;

    if (!$self->{mac02}) {
        $self->_populate_host_data or return;
    }

    if ($self->{mac02}) {
        return $self->{mac02};
    }
    else {
        $self->error($METHOD_UNSUPPORTED);
        return;
    }

} # }}}

# {{{ mac03 
#
sub mac03 {

    my $self = shift;

    # if mac01 is defined but mac03 isn't we aren't going to get it
    # this time around either

    if (!$self->{mac03} && !$self->{mac01}) {
        $self->_populate_host_data or return;
    }

    if ($self->{mac03}) {
        return $self->{mac03};
    }
    else {
        $self->error($METHOD_UNSUPPORTED);
        return;
    }

} # }}}

# {{{ mac04 
#
sub mac04 {

    my $self = shift;

    # see above

    if (!$self->{mac04} && !$self->{mac01}) {
        $self->_populate_host_data or return;
    }

    if ($self->{mac04}) {
        return $self->{mac04};
    }
    else {
        $self->error($METHOD_UNSUPPORTED);
        return;
    }

} # }}}

# {{{ macilo 
#
sub macilo {

    my $self = shift;

    if (!$self->{macilo}) {
        $self->_populate_host_data or return;
    }

    if ($self->{macilo}) {
        return $self->{macilo};
    }
    else {
        $self->error($METHOD_UNSUPPORTED);
        return;
    }

} # }}}

# {{{ model 
#
sub model {

    my $self = shift;

    if (!$self->{model}) {
        $self->_populate_host_data or return;
    }

    return $self->{model};

} # }}}

# {{{ mod_user 
#
sub mod_user {

    my $self = shift;

    if (@_) {

        my $arg_ref = shift;

        my $mod_username = $arg_ref->{username} || $self->username;
        my $mod_password = $arg_ref->{password} || $self->password;

        if (!$mod_username && !$mod_password) {

            croak "mod_user requires username to modify and new password";

        }

        my $ilo_command = qq|
            <USER_INFO MODE="write">
            <MOD_USER USER_LOGIN="$mod_username">
                <PASSWORD value="$mod_password"/>
            </MOD_USER>
            </USER_INFO>
        |;

        $ilo_command    = $self->_wrap($ilo_command);
        my $response    = $self->_send($ilo_command)    or return;
        my $xml         = $self->_serialize($response)  or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

        if ($self->username eq $mod_username) {

            $self->password($mod_password);

        }

    }
    else {

        croak "mod_user() requires parameters";

    }


    return 1;

} # }}}

# {{{ network 
#
sub network {

    my $self = shift;

    if (@_) {

        my $arg_ref = shift;

        my $domain_name = $arg_ref->{domain_name}   || $self->domain_name   or croak "domain_name not set";
        my $dns_name    = $arg_ref->{hostname}      || $self->hostname      or croak "name not set";
        my $dhcp_enable = $arg_ref->{dhcp_enabled}  || $self->dhcp_enabled  or croak "dhcp_enabled not set";
        my $ip_address  = $arg_ref->{ip_address}    || $self->ip_address    or croak "ip_address not set";
        my $subnet_mask = $arg_ref->{subnet_mask}   || $self->subnet_mask   or croak "subnet_mask not set";
        my $gateway     = $arg_ref->{gateway}       || $self->gateway       or croak "gateway not set";

        my @other_params;
        my @known_params = qw<
            dhcp_gateway     dhcp_dns_server
            prim_dns_server  sec_dns_server   ter_dns_server
            reg_ddns_server  reg_wins_server  gratuitous_arp
            speed_autoselect ping_gateway
        >;
        my @ilo3_params = qw<
            dhcp_sntp_settings  sntp_server1  sntp_server2  timezone
        >;

        # construct the XML commands for the given parameters
        for my $param (@known_params) {
            push @other_params, qq|<\U$param\E value="$arg_ref->{$param}"/>|
                if defined $arg_ref->{$param};
        }

        # detect iLO version if we don't know it yet
        $self->_version($self->_detect_version) if not $self->_version;

        # construct the XML commands for the given iLO3 parameters
        if ($self->_version >= 3) {
            for my $param (@ilo3_params) {
                push @other_params, qq|<\U$param\E value="$arg_ref->{$param}"/>|
                    if defined $arg_ref->{$param};
            }
        }

        my $other_params = join "\n                ", "", @other_params;
        my $ilo_command = qq|
            <RIB_INFO MODE="write">
            <MOD_NETWORK_SETTINGS>
                <DHCP_ENABLE value="$dhcp_enable"/>
                <IP_ADDRESS value="$ip_address"/>
                <SUBNET_MASK value="$subnet_mask"/>
                <GATEWAY_IP_ADDRESS value="$gateway"/>
                <DNS_NAME value="$dns_name"/>
                <DOMAIN_NAME value="$domain_name"/>
                $other_params
            </MOD_NETWORK_SETTINGS>
            </RIB_INFO>
        |;

        $ilo_command    = $self->_wrap($ilo_command);
        my $response    = $self->_send($ilo_command)    or return;
        my $xml         = $self->_serialize($response)  or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

        # force module to refresh new settings from the remote server
        foreach my $option_changed (keys %$arg_ref) {

            delete $self->{$option_changed};

        }

        # if IP was changed it should be updated, if not this won't hurt
        $self->address($ip_address);

    }

    return 1;

} # }}}

# {{{ new 
#
sub new {

    my ($class) = shift;

    # RT #65352: allow hash or hashref constructor args
    my %options = ref $_[0] ? %{$_[0]} : @_;

    my $self = {};

    bless($self, $class);

    $self->address(  $options{address}  );
    $self->username( $options{username} );
    $self->password( $options{password} );

    if ($options{port}) {
        $self->port($options{port});
    }
    else {
        $self->port(443);
    }

    # iLO version will be autodetected later if not specified
    $self->{_version} = $options{version} || undef; 
    $self->{_debug}   = $options{debug}   || '0';

    return $self;

} # }}}

# {{{ password 
#
sub password {

    my $self = shift;

    if ( @_ ) {
        $self->{password} = shift;
    }

    return $self->{password};

} # }}}

# {{{ port 
#
sub port {

    my $self = shift;

    if (@_) {
        my $port = shift;

        _port_is_valid($port) or croak "Port must be an integer between 0 and 65535";

        $self->{port} = $port;
    }

    return $self->{port};

} # }}}

# {{{ power 
#
sub power {

    my $self = shift;

    if ( @_ ) {

        my $state_requested = shift;

        my $ilo_command;

        if (lc($state_requested) eq 'on') {

            $ilo_command = $self->_generate_cmd('power_on');

        }
        elsif (lc($state_requested) eq 'off') {

            $ilo_command = $self->_generate_cmd('power_off');

        }
        elsif (lc($state_requested) eq 'reset') {

            $ilo_command = $self->_generate_cmd('power_reset');

        }
        else {

            croak "State '$state_requested' is not valid";

        }

        my $response = $self->_send($ilo_command)   or return;
        my $xml      = $self->_serialize($response) or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

        return $state_requested;

    }

    my $ilo_command = $self->_generate_cmd('power_status');

    my $response    = $self->_send($ilo_command)   or return;
    my $xml         = $self->_serialize($response) or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    my $state = $xml->{GET_HOST_POWER}->{HOST_POWER};

    if (!$state) {
        $self->error('Invalid response from remote ilo');
        return;
    }

    return lc($state);

} # }}}

# {{{ power_consumption 
#
sub power_consumption {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('power_consumption');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return unless $errmsg =~ /^Syntax error/;
    }

    if ( defined ( $xml->{GET_POWER_READINGS}->{PRESENT_POWER_READING}->{VALUE} ) ) {

        $self->{power_consumption} = $xml->{GET_POWER_READINGS}->{PRESENT_POWER_READING}->{VALUE};
        return $self->{power_consumption};

    }
    else {

        $self->error($METHOD_UNSUPPORTED);
        return;

    }

} # }}}

# {{{ power_supplies 
#
sub power_supplies {

    my $self = shift;

    if (!$self->{power_supplies}) {
        $self->_populate_embedded_health or return;
    }

    return $self->{power_supplies};

} # }}}

# {{{ prim_dns_server
#
sub prim_dns_server {

    my $self = shift;

    if (not defined $self->{prim_dns_server}) {
        $self->_populate_network_settings or return
    }

    return $self->{prim_dns_server}

} # }}}

# {{{ reg_ddns_server
#
sub reg_ddns_server {

    my $self = shift;

    if (not defined $self->{reg_ddns_server}) {
        $self->_populate_network_settings or return
    }

    return $self->{reg_ddns_server}

} # }}}

# {{{ reg_wins_server
#
sub reg_wins_server {
    my $self = shift;

    if (not defined $self->{reg_wins_server}) {
        $self->_populate_network_settings or return
    }

    return $self->{reg_wins_server}

} # }}}

# {{{ gratuitous_arp
#
sub gratuitous_arp {
    my $self = shift;

    if (not defined $self->{gratuitous_arp}) {
        $self->_populate_network_settings or return
    }

    return $self->{gratuitous_arp}

} # }}}

# {{{ speed_autoselect
#
sub speed_autoselect {
    my $self = shift;

    if (not defined $self->{speed_autoselect}) {
        $self->_populate_network_settings or return
    }

    return $self->{speed_autoselect}

} # }}}

# {{{ ping_gateway
#
sub ping_gateway {
    my $self = shift;

    if (not defined $self->{ping_gateway}) {
        $self->_populate_network_settings or return
    }

    return $self->{ping_gateway}

} # }}}

# {{{ ramslots 
#
sub ramslots {

    my $self = shift;

    if (!$self->{ramslots}) {
        $self->_populate_host_data or return;
    }

    return $self->{ramslots};

} # }}}

# {{{ raw_command 
#
sub raw_command {

    my $self = shift;
    my $cmd  = shift;

    unless ( $cmd ) {
        $self->error('No raw command specified');
        return;
    }

    my $ilo_command = $self->_generate_raw_cmd($cmd);

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    return $xml;

} # }}}

# {{{ reset 
#
sub reset {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('reset');

    my $response    = $self->_send($ilo_command)   or return;
    my $xml         = $self->_serialize($response) or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    return 1;

} # }}}

# {{{ sec_dns_server
#
sub sec_dns_server {

    my $self = shift;

    if (not defined $self->{sec_dns_server}) {
        $self->_populate_network_settings or return
    }

    return $self->{sec_dns_server}

} # }}}

# {{{ serial_cli_speed
#
sub serial_cli_speed {

    my $self = shift;
    return $self->_get_or_mod_global_settings(serial_cli_speed => @_)

} # }}}

# {{{ serial_cli_status
#
sub serial_cli_status {

    my $self = shift;
    return $self->_get_or_mod_global_settings(serial_cli_status => @_)

} # }}}

# {{{ serialID 
#
sub serialID {

    my $self = shift;

    if (!$self->{serialID}) {
        $self->_populate_host_data or return;
    }

    return $self->{serialID};

} # }}}

# {{{ server_name
#
sub server_name {
    my $self = shift;
    my $name = shift;
    my $ilo_command;

    if (defined $name) {
        # build iLO set command
        $ilo_command = qq|
            <SERVER_INFO MODE="write">
                <SERVER_NAME VALUE="$name"/>
            </SERVER_INFO>
        |;
    }
    else {
        # return cached value if available
        return $self->{server_name} if defined $self->{server_name};

        # build iLO get command
        $ilo_command = q|
            <SERVER_INFO MODE="read">
                <GET_SERVER_NAME/>
            </SERVER_INFO>
        |;
    }

    # send the command, read the response
    $ilo_command    = $self->_wrap($ilo_command);
    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if (my $errmsg = _check_errors($xml)) {
        $self->error($errmsg);
        return
    }

    # cache the value
    $self->{server_name} = defined $name ? $name : $xml->{SERVER_NAME}{VALUE};

    return $self->{server_name}

} # }}}

# {{{ session_timeout 
#
sub session_timeout {

    my $self = shift;

    if (!$self->{session_timeout}) {
        $self->_populate_global_settings or return;
    }

    return $self->{session_timeout};

} # }}}

# {{{ sntp_server1
#
sub sntp_server1 {
    my $self = shift;

    if (not defined $self->{sntp_server1}) {
        $self->_populate_network_settings or return
    }

    return $self->{sntp_server1}

} # }}}

# {{{ sntp_server2
#
sub sntp_server2 {
    my $self = shift;

    if (not defined $self->{sntp_server2}) {
        $self->_populate_network_settings or return
    }

    return $self->{sntp_server2}

} # }}}

# {{{ ssh_port 
#
sub ssh_port {

    my $self = shift;

    if (@_) {

        my $ssh_port = shift;

        _port_is_valid($ssh_port) or croak "ssh_port must be an integer between 0 and 65535";

        my $ilo_command = qq|
            <RIB_INFO MODE="write">
            <MOD_GLOBAL_SETTINGS>
                <SSH_PORT value="$ssh_port"/> 
            </MOD_GLOBAL_SETTINGS>
            </RIB_INFO>
        |;

        $ilo_command    = $self->_wrap($ilo_command);
        my $response    = $self->_send($ilo_command)    or return;
        my $xml         = $self->_serialize($response)  or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

        $self->{ssh_port} = $ssh_port;

    }

    if (!$self->{ssh_port}) {
        $self->_populate_global_settings or return;
    }

    return $self->{ssh_port};

} # }}}

# {{{ ssh_status 
#
sub ssh_status {

    my $self = shift;

    if (@_) {

        my $ssh_status = shift;

        my $ilo_command = qq|
            <RIB_INFO MODE="write">
            <MOD_GLOBAL_SETTINGS>
                <SSH_STATUS value="$ssh_status"/>
            </MOD_GLOBAL_SETTINGS>
            </RIB_INFO>
        |;

        $ilo_command    = $self->_wrap($ilo_command);
        my $response    = $self->_send($ilo_command)    or return;
        my $xml         = $self->_serialize($response)  or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

        $self->{ssh_status} = $ssh_status;

    }

    if (!$self->{ssh_status}) {
        $self->_populate_global_settings or return;
    }

    return $self->{ssh_status};

} # }}}

# {{{ subnet_mask 
#
sub subnet_mask {

    my $self = shift;

    if (!$self->{subnet_mask}) {
        $self->_populate_network_settings or return;
    }

    return $self->{subnet_mask};

} # }}}

# {{{ temperatures 
#
sub temperatures {

    my $self = shift;

    if (!$self->{temperatures}) {
        $self->_populate_embedded_health or return;
    }

    return $self->{temperatures};

} # }}}

# {{{ ter_dns_server 
#
sub ter_dns_server {
    my $self = shift;

    if (not defined $self->{ter_dns_server}) {
        $self->_populate_network_settings or return
    }

    return $self->{ter_dns_server}

} # }}}

# {{{ timezone 
#
sub timezone {
    my $self = shift;

    if (not defined $self->{timezone}) {
        $self->_populate_network_settings or return
    }

    return $self->{timezone}

} # }}}

# {{{ uid 
#
sub uid {

    my $self = shift;

    if (@_) {

        my $state_requested = shift;

        my $ilo_command;

        if ($state_requested eq 'on') {

            $ilo_command = $self->_generate_cmd('uid_on');

        }
        elsif ($state_requested eq 'off') {

            $ilo_command = $self->_generate_cmd('uid_off');

        }
        else {

            $self->error("State '$state_requested' is not valid");
            return;

        }

        my $response = $self->_send($ilo_command)   or return;
        my $xml      = $self->_serialize($response) or return;

        if ( my $errmsg = _check_errors($xml) ) {
            $self->error($errmsg);
            return;
        }

        return $state_requested;

    }

    my $ilo_command = $self->_generate_cmd('uid_status');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    my $uid_status = $xml->{GET_UID_STATUS}->{UID};

    return lc($uid_status);

} # }}}

# {{{ username 
#
sub username {

    my $self = shift;

    if (@_) {
        $self->{username} = shift;
    }

    return $self->{username};

} # }}}

# {{{ _check_errors 
#
sub _check_errors {

    my $xml = shift;

    my $errcode = $xml->{RESPONSE}->{STATUS};
    my $errmsg  = $xml->{RESPONSE}->{MESSAGE};

    if ($errcode ne '0x0000') {
        return $errmsg;
    }
    else {
        return;
    }

} # }}}

# {{{ _connect 
#
sub _connect {

    my $self = shift;

    if ($self->{_client}) {
        return $self->{_client};
    }

    my $address = $self->address or croak "Can't connect: address not set";
    my $port    = $self->port    or croak "Can't connect: port not set";

    $self->{_client} = IO::Socket::SSL->new(
        PeerAddr        => "$address:$port",
        SSL_verify_mode => SSL_VERIFY_NONE
    );

    if (!$self->{_client}) {
        $self->error( "Unable to establish SSL connection with $address:$port [" . IO::Socket::SSL::errstr() . "]" );
        return;
    }

    return $self->{_client};

} # }}}

# {{{ _debug 
#
sub _debug {

    my $self = shift;

    if (@_) {
        $self->{_debug} = shift;
    }

    return $self->{_debug};

} # }}}

# {{{ _detect_version 
#
sub _detect_version {

    my $self = shift;

    # iLO 3 has a slightly different interface; it requires that
    # you preface commands with an HTTP header

    my $ilo_command = qq(
        POST /ribcl HTTP/1.1
        HOST: localhost
        Content-length: 30
        Connection: Close

        <RIBCL VERSION="2.0"></RIBCL>
    );

    my $response = $self->_send($ilo_command) or return;

    if ($response =~ /^HTTP\/1.1 200 OK/) {
        return 3;
    }
    else {
        return 2;
    }

} # }}}

# {{{ _disconnect 
#
sub _disconnect {

    my $self = shift;

    my $client = $self->{_client} or return;

    $client->close;

    delete $self->{_client};

    return 1;

} # }}}

# {{{ _generate_cmd 
#
sub _generate_cmd {

    my ($self, $command) = @_;

    my %commands = (

        'get_embedded_health'   => qq( <SERVER_INFO MODE="read">
                                       <GET_EMBEDDED_HEALTH/>
                                       </SERVER_INFO> ),

        'get_fw_version'        => qq( <RIB_INFO MODE="read">
                                       <GET_FW_VERSION/>
                                       </RIB_INFO> ),

        'get_global_settings'   => qq( <RIB_INFO MODE="read">
                                       <GET_GLOBAL_SETTINGS/>
                                       </RIB_INFO> ),

        'get_host_data'         => qq( <SERVER_INFO MODE="read">
                                       <GET_HOST_DATA/>
                                       </SERVER_INFO> ),

        'get_network_settings'  => qq( <RIB_INFO MODE="read">
                                       <GET_NETWORK_SETTINGS/>
                                       </RIB_INFO> ),

        'power_consumption'     => qq( <SERVER_INFO MODE="read">
                                       <GET_POWER_READINGS/>
                                       </SERVER_INFO> ),

        'power_off'             => qq( <SERVER_INFO MODE="write">
                                       <SET_HOST_POWER HOST_POWER="No"/>
                                       </SERVER_INFO> ),

        'power_on'              => qq( <SERVER_INFO MODE="write">
                                       <SET_HOST_POWER HOST_POWER="Yes"/>
                                       </SERVER_INFO> ),

        'power_reset'           => qq( <SERVER_INFO MODE="write">
                                       <RESET_SERVER/>
                                       </SERVER_INFO> ),

        'power_status'          => qq( <SERVER_INFO MODE="read">
                                       <GET_HOST_POWER_STATUS/>
                                       </SERVER_INFO> ),

        'reset'                 => qq( <RIB_INFO MODE="write">
                                       <RESET_RIB/>
                                       </RIB_INFO> ),

        'uid_off'               => qq( <SERVER_INFO MODE="write">
                                       <UID_CONTROL UID="No"/>
                                       </SERVER_INFO> ),

        'uid_on'                => qq( <SERVER_INFO MODE="write">
                                       <UID_CONTROL UID="Yes"/>
                                       </SERVER_INFO> ),

        'uid_status'            => qq( <SERVER_INFO MODE="read">
                                       <GET_UID_STATUS/>
                                       </SERVER_INFO> ),

        'get_all_users'         => qq( <USER_INFO MODE="read">
                                       <GET_ALL_USERS/>
                                       </USER_INFO> ),

        'get_iml_log'           => qq( <SERVER_INFO MODE="read">
                                       <GET_EVENT_LOG/>
                                       </SERVER_INFO> ),

        'get_ilo_log'           => qq( <RIB_INFO MODE="read">
                                       <GET_EVENT_LOG/>
                                       </RIB_INFO> ),

        'get_oa_info'           => qq( <BLADESYSTEM_INFO MODE="read">
                                       <GET_OA_INFO/>
                                       </BLADESYSTEM_INFO> ),

    );

    my $ilo_command = $commands{$command} or die "Internal error: command '$command' doesn't exist";

    $ilo_command = $self->_wrap($ilo_command);

    return $ilo_command;

} # }}}

# {{{ _generate_raw_cmd 
#
# Pass in a command corresponding with one of the hash keys
# or pass in a chunk of xml.
#
sub _generate_raw_cmd {


    my ($self, $command) = @_;

    # The key names correspond to the filenames (currently
    # for read commands only) from the HP linux
    # LOsamplescripts bundle.
    #

    my %commands = (

        ERS_Get_Settings => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_ERS_SETTINGS />
                                </RIB_INFO> ],

        Get_2Factor => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_TWOFACTOR_SETTINGS/>
                                </RIB_INFO> ],

        Get_All_Languages => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_ALL_LANGUAGES/>
                                </RIB_INFO> ],

        Get_All_Licenses => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_ALL_LICENSES/>
                                </RIB_INFO> ],

        Get_All_User_Info => 

                            qq[ <USER_INFO MODE="read">
                                <GET_ALL_USER_INFO/>
                                </USER_INFO> ],

        Get_All_Users => 

                            qq[ <USER_INFO MODE="read">
                                <GET_ALL_USERS/>
                                </USER_INFO> ],

        Get_Asset_Tag => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_ASSET_TAG />
                                </SERVER_INFO> ],

        Get_Boot_Mode => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_PENDING_BOOT_MODE/>
                                </SERVER_INFO> ],

        Get_Cert_Subject_Info => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_CERT_SUBJECT_INFO/>
                                </RIB_INFO> ],

        Get_Current_Boot_Mode => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_CURRENT_BOOT_MODE/>
                                </SERVER_INFO> ],

        Get_Diagport => 

                            qq[ <RACK_INFO MODE="read">
                                <GET_DIAGPORT_SETTINGS/>
                                </RACK_INFO> ],

        Get_Directory => 

                            qq[ <DIR_INFO MODE="read">
                                <GET_DIR_CONFIG/>
                                </DIR_INFO> ],

        Get_EmHealth => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_EMBEDDED_HEALTH />
                                </SERVER_INFO> ],

        Get_Embedded_Health => 

                            qq[ <SERVER_INFO MODE="read">
                                GET_EMBEDDED_HEALTH>
                                <GET_ALL_FANS/>
                                <GET_ALL_TEMPERATURES/>
                                <GET_ALL_POWER_SUPPLIES/>
                                <GET_ALL_VRM/>
                                <GET_ALL_PROCESSORS/>
                                <GET_ALL_MEMORY/>
                                <GET_ALL_NICS/>
                                <GET_ALL_STORAGE/>
                                <GET_ALL_HEALTH_STATUS/>
                                <GET_ALL_FIRMWARE_VERSIONS/>
                                </GET_EMBEDDED_HEALTH> ],

        Get_Enc_Bay_IP_Settings => 

                            qq[ <RACK_INFO MODE="read">
                                <GET_ENCLOSURE_IP_SETTINGS/>
                                </RACK_INFO> ],

        Get_Encrypt => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_ENCRYPT_SETTINGS/>
                                </RIB_INFO> ],

        Get_FIPS_Status => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_FIPS_STATUS/>
                                </RIB_INFO> ],

        Get_FW_Version => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_FW_VERSION/>
                                </RIB_INFO> ],

        Get_Federation_All_Groups => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_FEDERATION_ALL_GROUPS/>
                                </RIB_INFO> ],

        Get_Federation_All_Groups_Info => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_FEDERATION_ALL_GROUPS_INFO/>
                                </RIB_INFO> ],

        Get_Federation_Group => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_FEDERATION_GROUP GROUP_NAME="groupname"/>
                                </RIB_INFO> ],

        Get_Federation_Multicast_Options => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_FEDERATION_MULTICAST/>
                                </RIB_INFO> ],

        Get_Global => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_GLOBAL_SETTINGS/>
                                </RIB_INFO> ],

        Get_Host_APO => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_SERVER_AUTO_PWR />
                                </SERVER_INFO> ],

        Get_Host_Data => 

                            qq[ <SERVER_INFO MODE="READ" >
                                <GET_HOST_DATA />
                                </SERVER_INFO> ],

        Get_Host_Power => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_HOST_POWER_STATUS/>
                                </SERVER_INFO> ],

        Get_Host_Power_Reg_Info => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_HOST_POWER_REG_INFO/>
                                </SERVER_INFO> ],

        Get_Host_Power_Saver => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_HOST_POWER_SAVER_STATUS/>
                                </SERVER_INFO> ],

        Get_Host_Pwr_Micro_Ver => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_HOST_PWR_MICRO_VER/>
                                </SERVER_INFO> ],

        Get_Hotkey_Config => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_HOTKEY_CONFIG/>
                                </RIB_INFO> ],

        Get_IML => 

                            qq[ <SERVER_INFO MODE="READ" >
                                <GET_EVENT_LOG />
                                </SERVER_INFO> ],

        Get_Network => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_NETWORK_SETTINGS/>
                                </RIB_INFO> ],

        Get_OA_Info => 

                            qq[ <BLADESYSTEM_INFO MODE="read">
                                <GET_OA_INFO/>
                                </BLADESYSTEM_INFO> ],

        Get_One_Time_Boot_Order => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_ONE_TIME_BOOT/>
                                </SERVER_INFO> ],

        Get_Persistent_Boot_Order => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_PERSISTENT_BOOT/>
                                </SERVER_INFO> ],

        Get_Persmouse_Status => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_PERS_MOUSE_KEYBOARD_ENABLED/>
                                </SERVER_INFO> ],

        Get_PowerCap => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_POWER_CAP/>
                                </SERVER_INFO> ],

        Get_Power_On_Time => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_SERVER_POWER_ON_TIME />
                                </SERVER_INFO> ],

        Get_Power_Readings => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_POWER_READINGS/>
                                </SERVER_INFO> ],

        Get_Product_Name => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_PRODUCT_NAME/>
                                </SERVER_INFO> ],

        Get_Pwreg_Alert_Threshold => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_PWREG/>
                                </SERVER_INFO> ],

        Get_Rack_Settings => 

                            qq[ <RACK_INFO MODE="read">
                                <GET_RACK_SETTINGS/>
                                </RACK_INFO> ],

        Get_SNMP_IM => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_SNMP_IM_SETTINGS/>
                                </RIB_INFO> ],

        Get_SSO_Settings => 

                            qq[ <SSO_INFO MODE="read">
                                <GET_SSO_SETTINGS/>
                                </SSO_INFO> ],

        Get_Security_Msg => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_SECURITY_MSG/>
                                </RIB_INFO> ],

        Get_Server_FQDN => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_SERVER_FQDN />
                                <GET_SMH_FQDN />
                                </SERVER_INFO> ],

        Get_Server_Name => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_SERVER_NAME/>
                                </SERVER_INFO> ],

        Get_Supported_Boot_Mode => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_SUPPORTED_BOOT_MODE/>
                                </SERVER_INFO> ],

        Get_TPM_Status => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_TPM_STATUS/>
                                </SERVER_INFO> ],

        Get_UID_Status => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_UID_STATUS />
                                </SERVER_INFO> ],

        Get_User => 

                            qq[ <USER_INFO MODE="read">
                                <GET_USER USER_LOGIN="username"/>
                                </USER_INFO> ],

        Get_VM_Status => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_VM_STATUS DEVICE="FLOPPY"/>
                                </RIB_INFO> ],

        Get_iLO_Log => 

                            qq[ <RIB_INFO MODE="READ" >
                                <GET_EVENT_LOG />
                                </RIB_INFO> ],

        Get_language => 

                            qq[ <RIB_INFO MODE="read">
                                <GET_LANGUAGE/>
                                </RIB_INFO> ],

        Profile_Apply_Get_Results => 

                            qq[ <RIB_INFO MODE="read">
                                <PROFILE_APPLY_GET_RESULTS/>
                                </RIB_INFO> ],

        Profile_Desc_List => 

                            qq[ <RIB_INFO MODE="read">
                                <PROFILE_LIST/>
                                </RIB_INFO> ],

        get_discovery_services => 

                            qq[ <SERVER_INFO MODE="read">
                                <GET_SPATIAL/>
                                </SERVER_INFO> ],


    );

    my $ilo_command = 
        defined $commands{$command}
        &&      $commands{$command}
              ? $commands{$command}
              : $command
              ;
            
    $ilo_command = $self->_wrap($ilo_command);

    return $ilo_command;

} # }}}

# {{{ _get_or_mod_global_settings 
#
sub _get_or_mod_global_settings {
    my $self = shift;
    my $param = shift;

    if (@_) {
        my $value = shift;

        my $ilo_command = qq|
            <RIB_INFO MODE="write">
            <MOD_GLOBAL_SETTINGS>
                <\U$param\E value="$value"/>
            </MOD_GLOBAL_SETTINGS>
            </RIB_INFO>
        |;

        $ilo_command    = $self->_wrap($ilo_command);
        my $response    = $self->_send($ilo_command)    or return;
        my $xml         = $self->_serialize($response)  or return;

        if (my $errmsg = _check_errors($xml)) {
            $self->error($errmsg);
            return
        }

        $self->{$param} = $value;
    }

    if (not defined $self->{$param}) {
        $self->_populate_global_settings or return;
    }

    return $self->{$param}
} # }}}

# {{{ _length 
#
sub _length {

    # for iLO 3 we need to know the length of the XML for the
    # Content-length field in the http header

    my ($self, $ilo_command) = @_;

    my $length = 0;

    foreach my $line (split(/\n/, $ilo_command)) {

        $line =~ s/^\s+//;
        $line =~ s/\s+$//;

        # each line has \r\n appended when sending, so + 2
        $length += length($line) + 2;

    }

    return $length;

} # }}}

# {{{ _populate_embedded_health 
#
sub _populate_embedded_health {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('get_embedded_health');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    my $backplanes;
    my $controllers;
    my $fans            = $xml->{GET_EMBEDDED_HEALTH_DATA}->{FANS}->{FAN};
    my $power_supplies  = $xml->{GET_EMBEDDED_HEALTH_DATA}->{POWER_SUPPLIES}->{SUPPLY};
    my $temperatures    = $xml->{GET_EMBEDDED_HEALTH_DATA}->{TEMPERATURE}->{TEMP};

    $backplanes         = $xml->{GET_EMBEDDED_HEALTH_DATA}->{DRIVES}->{BACKPLANE} if ( exists($xml->{GET_EMBEDDED_HEALTH_DATA}->{DRIVES}));
    $controllers        = $xml->{GET_EMBEDDED_HEALTH_DATA}->{STORAGE}->{CONTROLLER} if ( exists($xml->{GET_EMBEDDED_HEALTH_DATA}->{STORAGE}) );

    $fans               = [] unless defined( $fans );
    $backplanes         = [] unless defined( $backplanes );
    $controllers        = [] unless defined( $controllers );
    $power_supplies     = [] unless defined( $power_supplies );
    $temperatures       = [] unless defined( $temperatures );
    
    # XML::Simple makes wrong guesses if e.g. only one FAN is present...
    $fans               = [ $fans           ] unless reftype( $fans )           eq 'ARRAY';
    $backplanes         = [ $backplanes     ] unless reftype( $backplanes )     eq 'ARRAY';
    $controllers        = [ $controllers    ] unless reftype( $controllers )    eq 'ARRAY';
    $power_supplies     = [ $power_supplies ] unless reftype( $power_supplies ) eq 'ARRAY';
    $temperatures       = [ $temperatures   ] unless reftype( $temperatures )   eq 'ARRAY';
    
    $self->{controllers}  = [] unless ( exists( $self->{controllers} ) );
    foreach my $controller (@$controllers) {

        my @logical_drives;
        my $logical_drives;
        $logical_drives = $controller->{ LOGICAL_DRIVE } if ( exists( $controller->{ LOGICAL_DRIVE } ) );
        $logical_drives = [] unless defined( $logical_drives );
        $logical_drives = [ $logical_drives ] unless reftype( $logical_drives ) eq 'ARRAY';

        foreach my $logical_drive ( @$logical_drives ) {

            my @physical_drives;
            my $physical_drives;
            $physical_drives = $logical_drive->{ PHYSICAL_DRIVE }; # if ( exists( $logical_drive->{ PHYSICAL_DRIVE } ) );
            $physical_drives = [] unless defined( $physical_drives );
            $physical_drives = [ $physical_drives ] unless reftype( $physical_drives ) eq 'ARRAY';

            foreach my $physical_drive ( @$physical_drives ) {

                push( @physical_drives, {
                    label         => $physical_drive->{ LABEL }->{ VALUE },
                    status        => $physical_drive->{ STATUS }->{ VALUE },
                    serial_number => $physical_drive->{ SERIAL_NUMBER }->{ VALUE },
                    model         => $physical_drive->{ MODEL }->{ VALUE },
                    capacity      => $physical_drive->{ CAPACITY }->{ VALUE },
                    location      => $physical_drive->{ LOCATION }->{ VALUE },
                    fw_version    => $physical_drive->{ FW_VERSION }->{ VALUE },
                });

            }

            push( @logical_drives, {
                label    => $logical_drive->{ LABEL }->{ VALUE },
                status   => $logical_drive->{ STATUS }->{ VALUE },
                capacity => $logical_drive->{ CAPACITY }->{ VALUE },
                physical_drives => \@physical_drives,
            });

        }

        push( @{$self->{controllers}}, {
            label                   => $controller->{ LABEL }->{ VALUE },
            status                  => $controller->{ STATUS }->{ VALUE },
            serial_number           => $controller->{ SERIAL_NUMBER }->{ VALUE },
            model                   => $controller->{ MODEL }->{ VALUE },
            fw_version              => $controller->{ FW_VERSION }->{ VALUE },
            cache_module_status     => $controller->{ CACHE_MODULE_STATUS }->{ VALUE },
            cache_module_serial_num => $controller->{ CACHE_MODULE_SERIAL_NUM }->{ VALUE },
            cache_module_memory     => $controller->{ CACHE_MODULE_MEMORY }->{ VALUE },
            logical_drives => \@logical_drives,
        });
    }

    $self->{backplanes} = [] unless ( exists( $self->{backplanes} ) );
    foreach my $backplane (@$backplanes) {

        my $firmware_version = $backplane->{FIRMWARE_VERSION}->{VALUE};
        my $enclosure_adr    = $backplane->{ENCLOSURE_ADDR}->{VALUE};
        my @disks;

        next unless ( ($firmware_version =~ /^\d+\.\d+$/) && ($enclosure_adr =~ /^\d+$/) );

        foreach my $index ( 0..$#{$backplane->{ DRIVE_BAY }} ) {
            push( @disks, {
                drive_bay  => $backplane->{ DRIVE_BAY }[ $index ]->{ VALUE }, 
                product_id => $backplane->{ PRODUCT_ID }[ $index ]->{ VALUE },
                status     => $backplane->{ STATUS }[ $index ]->{ VALUE }, 
                isOk       => ( $backplane->{ STATUS }[ $index ]->{ VALUE } eq "Ok" ), 
                uid_led    => $backplane->{ UID_LED }[ $index ]->{ VALUE }, 
            });

        }

        push( @{$self->{backplanes}}, {
            firmware_version => $firmware_version,
            enclosure_adr    => $enclosure_adr,
            disks            => \@disks,
        });

    }

    foreach my $fan (@$fans) {

        my $location = $fan->{ZONE}->{VALUE};
        my $name     = $fan->{LABEL}->{VALUE};
        my $speed    = $fan->{SPEED}->{VALUE};
        my $status   = $fan->{STATUS}->{VALUE};
        my $unit     = $fan->{SPEED}->{UNIT};

        next unless $speed && $speed =~ /^\d+$/;

        push( @{$self->{fans}}, {
            'location'  => $location,
            'name'      => $name,
            'speed'     => $speed,
            'status'    => $status,
            'unit'      => $unit,
        });

    }

    foreach my $power_supply (@$power_supplies) {

        my $name     = $power_supply->{LABEL}->{VALUE};
        my $status   = $power_supply->{STATUS}->{VALUE};

        next if $status eq 'Not Installed';

        push( @{$self->{power_supplies}}, {
            'name'   => $name,
            'status' => $status,
        });

    }

    foreach my $temperature (@$temperatures) {

        my $name     = $temperature->{LABEL}->{VALUE};
        my $location = $temperature->{LOCATION}->{VALUE};
        my $value    = $temperature->{CURRENTREADING}->{VALUE};
        my $unit     = $temperature->{CURRENTREADING}->{UNIT};
        my $caution  = $temperature->{CAUTION}->{VALUE};
        my $critical = $temperature->{CRITICAL}->{VALUE};
        my $status   = $temperature->{STATUS}->{VALUE};

        next unless $value && $value =~ /^\d+$/;

        push( @{$self->{temperatures}}, {
            'name'      => $name,
            'location'  => $location,
            'value'     => $value,
            'unit'      => $unit,
            'caution'   => $caution,
            'critical'  => $critical,
            'status'    => $status,
        });

    }

    return 1;

} # }}}

# {{{ _populate_fw_version 
#
sub _populate_fw_version {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('get_fw_version');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    $self->{fw_type}    = $xml->{GET_FW_VERSION}->{MANAGEMENT_PROCESSOR};
    $self->{fw_date}    = $xml->{GET_FW_VERSION}->{FIRMWARE_DATE};
    $self->{fw_version} = $xml->{GET_FW_VERSION}->{FIRMWARE_VERSION};

    return 1;

} # }}}

# {{{ _populate_global_settings 
#
sub _populate_global_settings {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('get_global_settings');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    my @fields = qw<
         https_port  http_port  ssh_port  ssh_status  rbsu_post_ip  enforce_aes
         f8_prompt_enabled  f8_login_required  authentication_failure_logging
         remote_console_port  serial_cli_speed  serial_cli_status
         session_timeout  min_password  ilo_funct_enabled  virtual_media_port
    >;

    foreach my $field (@fields) {

        $self->{$field} = $xml->{GET_GLOBAL_SETTINGS}{uc $field}{VALUE}
            if exists $xml->{GET_GLOBAL_SETTINGS}{uc $field};

    }

    return 1;

} # }}}

# {{{ _populate_host_data 
#
sub _populate_host_data {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('get_host_data');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    # SMBIOS data is stored in a big fat array
    #
    # data is not guaranteed to be in any particular index, so we have to
    # iterate through all the data looking for certain fields.
    #
    # thankfully, SMBIOS *types* are standard (eg. CPU data is type 4)
    # so we have a starting point
    #
    # this really sucks but I don't know of a better way

    for my $fieldnum (0 .. scalar @{$xml->{GET_HOST_DATA}->{SMBIOS_RECORD}}) {

        my $smbios_data = $xml->{GET_HOST_DATA}->{SMBIOS_RECORD}[$fieldnum]->{FIELD};
        my $smbios_type = $xml->{GET_HOST_DATA}->{SMBIOS_RECORD}[$fieldnum]->{TYPE};

        next unless defined $smbios_type;

        if ($smbios_type == 0) {

            for my $entry (0 .. scalar @$smbios_data) {

                my $field_name  = $smbios_data->[$entry]->{NAME};
                my $field_value = $smbios_data->[$entry]->{VALUE};

                next unless $field_name && $field_value;

                if ($field_name eq 'Date') {
                    $self->{biosdate} = $field_value;
                }

            }

        }
        elsif ($smbios_type == 1) {

            for my $entry (0 .. scalar @$smbios_data) {

                my $field_name  = $smbios_data->[$entry]->{NAME};
                my $field_value = $smbios_data->[$entry]->{VALUE};

                next unless $field_name && $field_value;

                if ($field_name eq 'Product Name') {
                    $self->{model}      = $field_value;
                }
                elsif ($field_name eq 'Serial Number') {
                    $self->{serialID}   = $field_value;
                }
                elsif ($field_name eq 'UUID') {
                    $self->{UUID}       = $field_value;
                }

            }

        }
        elsif ($smbios_type == 4) {

            my ($name, $speed, $cores);

            for my $entry (0 .. scalar @$smbios_data) {

                my $field_name  = $smbios_data->[$entry]->{NAME};
                my $field_value = $smbios_data->[$entry]->{VALUE};

                next unless $field_name && $field_value;

                if ($field_name eq 'Label') {
                    $name  = $field_value;
                }
                elsif ($field_name eq 'Speed') {
                    $speed = $field_value;
                }
                elsif ($field_name eq 'Execution Technology') {
                    $cores = $field_value || 'single core';
                }

            }

            # otherwise slot is empty
            next unless $speed && $speed =~ /^[1-9]/;

            push( @{$self->{cpus}}, {
                'name'  => $name,
                'speed' => $speed,
                'cores' => $cores }
            );

        }
        elsif ($smbios_type == 17) {

            my ($location, $size, $speed);

            for my $entry (0 .. scalar @$smbios_data) {

                my $field_name  = $smbios_data->[$entry]->{NAME};
                my $field_value = $smbios_data->[$entry]->{VALUE};

                next unless $field_name && $field_value;

                if ($field_name eq 'Label') {
                    $location = $field_value;
                }
                elsif ($field_name eq 'Size') {
                    $size     = $field_value;
                }
                elsif ($field_name eq 'Speed') {
                    $speed    = $field_value;
                }

            }

            push( @{$self->{ramslots}}, {
                'location'  => $location,
                'size'      => $size,
                'speed'     => $speed }
            );

        }
        elsif ($smbios_type == 209) {

            for my $entry (0 .. scalar @$smbios_data) {

                my $field_name  = $smbios_data->[$entry]->{NAME};
                my $field_value = $smbios_data->[$entry]->{VALUE};

                next unless $field_name && $field_value;
                next unless $field_name eq 'Port';

                # MAC address is offset by one from port label

                my $current_mac = $smbios_data->[$entry + 1]->{VALUE};

                if ($field_value eq '1') {
                    $self->{mac01} = $current_mac;
                }
                elsif ($field_value eq '2') {
                    $self->{mac02} = $current_mac;
                }
                elsif ($field_value eq '3') {
                    $self->{mac03} = $current_mac;
                }
                elsif ($field_value eq '4') {
                    $self->{mac04} = $current_mac;
                }
                elsif ($field_value eq 'iLO') {
                    $self->{macilo} = $current_mac;
                }

            }

        }

    }

    ($self->{mac01}  = lc($self->{mac01}  || "")) =~ tr/-/:/;
    ($self->{mac02}  = lc($self->{mac02}  || "")) =~ tr/-/:/;
    ($self->{mac03}  = lc($self->{mac03}  || "")) =~ tr/-/:/;
    ($self->{mac04}  = lc($self->{mac04}  || "")) =~ tr/-/:/;
    ($self->{macilo} = lc($self->{macilo} || "")) =~ tr/-/:/;

    return 1;

} # }}}

# {{{ _populate_network_settings 
#
sub _populate_network_settings {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('get_network_settings');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    my @fields = qw( dhcp_dns_server     dhcp_gateway    dns_name
                     dhcp_domain_name    ip_address      domain_name
                     dhcp_enable         subnet_mask     gateway_ip_address
                     dhcp_gateway        dhcp_dns_server
                     prim_dns_server     sec_dns_server  ter_dns_server
                     dhcp_sntp_settings  sntp_server1    sntp_server2
                     timezone            reg_ddns_server reg_wins_server
                     gratuitous_arp      ping_gateway
    );

    foreach my $field (@fields) {
        my $xml_field = uc $field;
        $self->{$field} = $xml->{GET_NETWORK_SETTINGS}->{$xml_field}->{VALUE}
            if exists $xml->{GET_NETWORK_SETTINGS}{$xml_field};
    }

    return 1;

} # }}}

# {{{ _populate_oa_info 
#
sub _populate_oa_info {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('get_oa_info');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    return unless defined $xml->{GET_OA_INFO}
               && defined $xml->{GET_OA_INFO}->{ENCL}
               && defined $xml->{GET_OA_INFO}->{ipAddress};

    my $ENCL      = $xml->{GET_OA_INFO}->{ENCL};
    my $ipAddress = $xml->{GET_OA_INFO}->{ipAddress};

    my $RACK = 
        defined $xml->{GET_OA_INFO}->{RACK}
        &&      $xml->{GET_OA_INFO}->{RACK}
              ? $xml->{GET_OA_INFO}->{RACK}
              : undef;

    my $ST = 
        defined $xml->{GET_OA_INFO}->{ST}
        &&      $xml->{GET_OA_INFO}->{ST}
              ? $xml->{GET_OA_INFO}->{ST}
              : undef;

    my $Location = 
        defined $xml->{GET_OA_INFO}->{Location}
        &&      $xml->{GET_OA_INFO}->{Location}
              ? $xml->{GET_OA_INFO}->{Location}
              : undef;

    my $macAddress = 
        defined $xml->{GET_OA_INFO}->{macAddress}
        &&      $xml->{GET_OA_INFO}->{macAddress}
              ? $xml->{GET_OA_INFO}->{macAddress}
              : undef;

    my $uidStatus = 
        defined $xml->{GET_OA_INFO}->{uidStatus}
        &&      $xml->{GET_OA_INFO}->{uidStatus}
              ? $xml->{GET_OA_INFO}->{uidStatus}
              : undef;

    my $oa_info = "${ENCL} (${ipAddress}";
    $oa_info .= " - ${macAddress}"       if $macAddress;
    $oa_info .= ")";
    $oa_info .= " Rack: ${RACK}"         if $RACK;
    $oa_info .= " Location: ${Location}" if $Location;
    $oa_info .= " ST: ${ST}"             if $ST;
    $oa_info .= " UID: ${uidStatus}"     if $uidStatus;

    
    $self->{oa_info} = $oa_info;

    return 1;

} # }}}

# {{{ _populate_all_users 
#
sub _populate_all_users {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('get_all_users');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

   #$self->{all_users} = $xml;

    return unless 
           defined $xml
        && defined $xml->{GET_ALL_USERS}
        && defined $xml->{GET_ALL_USERS}->{USER_LOGIN}
        &&     ref $xml->{GET_ALL_USERS}->{USER_LOGIN} eq 'ARRAY';

    for my $cur ( @{$xml->{GET_ALL_USERS}->{USER_LOGIN}} ) {

        my $user =
            defined $cur->{VALUE}
            &&      $cur->{VALUE}
                  ? $cur->{VALUE}
                  : next
                  ;

        push @{$self->{all_users}}, $user;

    }

    return 1;

} # }}}

# {{{ _populate_iml_log 
#
sub _populate_iml_log {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('get_iml_log');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    if ( my $log = $self->_parse_log($xml) ) {
        $self->{iml_log} = $log;
        return 1;
    } else {
        return;
    }

} # }}}

# {{{ _populate_ilo_log 
#
sub _populate_ilo_log {

    my $self = shift;

    my $ilo_command = $self->_generate_cmd('get_ilo_log');

    my $response    = $self->_send($ilo_command)    or return;
    my $xml         = $self->_serialize($response)  or return;

    if ( my $errmsg = _check_errors($xml) ) {
        $self->error($errmsg);
        return;
    }

    if ( my $log = $self->_parse_log($xml) ) {
        $self->{ilo_log} = $log;
        return 1;
    } else {
        return;
    }


} # }}}

# {{{ _send 
#
sub _send {

    my ($self, $ilo_command) = @_;

    my $client = $self->_connect or return;

    my @sent_lines;

    foreach my $line ( split(/\n/, $ilo_command) ) {

        $line =~ s/^\s+//;
        $line =~ s/\s+$//;

        push @sent_lines, $line if $line;

        if ($self->_debug > 0) {
            print "'$line'\n";
        }

        my $ok = print {$client} $line . "\r\n";

        if (!$ok) {
            $self->error("Error transmitting command to server");
            return;
        }

    }

    chomp( my $response = join('', <$client>) );

    # iLO 3 returns a chunked http response
    # rather than parse it, just filter out the chunking data
    # janky, but a lightweight solution which works for all iLO versions

    $response =~ s/[\r\n]+[0-9a-f]{3}[\r\n]+//gs;

    $self->_disconnect or die "Internal error: disconnect failed, wtf!";

    if (!$response) {
        $self->error("No response received from remote machine");
        return;
    }


    if ($self->_debug > 0) {

        print Dumper $response;

        my @recv_lines;

        # Break the response up into stanzas a bit like the
        # _serialize() function.
        #
        for my $cur ( grep { !/HTTP\/1.1/ } split(/<\?xml.*?\?>/, $response) ) {
            $cur =~ s/\R//g;
            $cur =~ s/\s\s+/ /g;
            push @recv_lines, $cur if $cur;
        }

        # Now iterate the indexes of sent_lines and display
        # the corresponding sent and receive messages.
        #
        for ( 0..$#sent_lines ) {

            print 'Sent: ' . $sent_lines[$_] . "\n";

            my $recd =
                defined $recv_lines[$_]
                &&      $recv_lines[$_]
                      ? $recv_lines[$_]
                      : 'N/A'
                      ;

            print "Recd: ${recd}\n\n";

        }

    }

    return $response;

} # }}}

# {{{ _serialize 
#
sub _serialize {

    my ($self, $data) = @_;

    if (!$data) {
        $self->error('Error parsing response: no data received');
        return;
    }

    # Since iLO might sometimes return this <INFORM> section, it can make that
    # response the largest. As a result, the longest compare below might pick
    # the wrong XML block. Therefore, we strip the <INFORM> section.
    $data =~ s/<INFORM>Scripting utility should be updated to the latest version\.<\/INFORM>//g;

    # iLO returns multiple XML stanzas, all starting with a standard header.
    # We first need to break this glob of data into individual XML components,
    # while ignoring the HTTP header returned by iLO 3.

    chomp( my @stanzas = grep { !/HTTP\/1.1/ } split(/<\?xml.*?\?>/, $data) );

    # @stanzas now contains a number of valid XML sequences.
    # All but one is unnecessary; they contain short status messages and
    # nothing else. So, we want to parse only the longest message.
    #
    # NB: The same status codes are also included in the longest stanza.

    my $longest = ( sort {length($b) <=> length($a)} @stanzas )[0];

    if ($self->_debug > 3) {
        print Dumper $longest;
    }

    # XML::Simple croaks if it can't parse the data properly.
    # We want to capture any errors and propagate them on our own terms.

    my $xml;

    eval { $xml = XMLin( $longest, NormaliseSpace => 2 ) };

    if ($EVAL_ERROR) {
        $self->error("Error parsing response: $EVAL_ERROR");
        return;
    }

    if ($self->_debug >= 2) {
        print Dumper $xml;
    }

    return $xml;

} # }}}

# {{{ _parse_log 
#
# Turn the logs from the parsed xml into a more syslog-like output. 
#
# Expects to receive the xml as an argument.
#
# Returns a scalar ref of the log lines ready for printing.
#
sub _parse_log {

    my ($self, $xml) = @_;

    return unless 
               defined $xml->{EVENT_LOG}
            && defined $xml->{EVENT_LOG}->{EVENT}
            &&     ref $xml->{EVENT_LOG}->{EVENT} eq 'ARRAY';


    my $parsed = '';

    my $addr = $self->address;

    for my $event ( @{$xml->{EVENT_LOG}->{EVENT}} ) {

        my $SEVERITY       = $event->{SEVERITY} . ' -';
        my $CLASS          = '[' . $event->{CLASS} . ']';
        my $INITIAL_UPDATE = $event->{INITIAL_UPDATE};
        my $LAST_UPDATE    = $event->{LAST_UPDATE};
        my $DESCRIPTION    = $event->{DESCRIPTION};
        my $COUNT          = $event->{COUNT};

        $parsed .= join(' ', $LAST_UPDATE, $addr, $CLASS, $SEVERITY, $DESCRIPTION, "\n" );

        if ( $COUNT > 1 ) {
            $parsed .= join(' ', $LAST_UPDATE, $addr, $CLASS, $SEVERITY, "Last message repeated ${COUNT} times.\n" );
        }

    }

    return \$parsed;

} # }}}

# {{{ _port_is_valid 
#
sub _port_is_valid {

    my $port = shift;

    return unless defined $port && $port =~ /^\d{1,5}$/ && $port <= 65535;

    return 1;

} # }}}

# {{{ _version 
#
sub _version {

    my $self = shift;

    if (@_) {
        $self->{_version} = shift;
    }

    return $self->{_version};

} # }}}

# {{{ _wrap 
#
sub _wrap {

    my $self = shift;

    my $body = shift or die "Internal error: no data passed to _wrap()";

    my $username = $self->username or croak "Username not set";
    my $password = $self->password or croak "Password not set";

    if (!$self->_version) {

        my $ilo_version = $self->_detect_version or return;

        print "Detected iLO version $ilo_version\n" if $self->_debug > 2;

        $self->_version($ilo_version);

    }

    my $header = qq|
        <?xml version="1.0"?>
        <LOCFG version="2.21">
        <RIBCL VERSION="2.0">
        <LOGIN USER_LOGIN="$username" PASSWORD="$password">
    |;

    my $footer = qq|
        </LOGIN>
        </RIBCL>
    |;

    my $ilo_command = $header . $body . $footer;

    if ($self->_version == 3) {

        my $command_length = $self->_length($ilo_command);

        my $http_header = qq|
            POST /ribcl HTTP/1.1
            HOST: localhost
            Content-length: $command_length
            Connection: Close

        |;

        $ilo_command = $http_header . $ilo_command;

    }

    return $ilo_command;

} # }}}

# {{{ DESTROY 
#
sub DESTROY {

    my $self = shift;

    my $client = $self->{_client} or return;
    $client->close;

    return;
} # }}}

1;

__END__

=head1 NAME

Net::ILO - Interface to HP Integrated Lights-Out

=head1 SYNOPSIS

    use Net::ILO;

    my $ilo = Net::ILO->new({
        address     => '192.168.128.10',
        username    => 'Administrator',
        password    => 'secret',
    });

    # returns 'on' or 'off'
    my $power_status = $ilo->power or die $ilo->error;

    $ilo->power('off');
    $ilo->power('reset');

    my $mac01  = $ilo->mac01;
    my $mac02  = $ilo->mac02;
    my $macilo = $ilo->macilo;

    # see METHODS for complete listing

=head1 DESCRIPTION

The Net::ILO module is an interface to a subset of Hewlett-Packards
Integrated Lights-Out out-of-band management system. HP's API is XML-based
and cumbersome to use; this module aims to simplify accessing
the iLO from Perl while retaining as much functionality as possible.

Not every iLO function is implemented here, however most common ones are.

This module is based on the sixth edition of the "HP Integrated Lights-Out
Management Processor Scripting and Command Line Resource Guide" and has
been successfully tested with the following server types:

    DL360/G3
    DL360/G4
    DL360/G4p
    DL360/G5
    DL360/G6
    DL360/G7 ** see note below
    DL380/G3
    DL380/G4
    DL380/G5

It should work with other server models; feedback (either way) is much
appreciated.

Note: iLO 3 support is in BETA, and still being tested.

=head1 INTERFACE QUIRKS

Wherever possible, I have mimicked HP's API to maintain consistency. However,
certain names have been changed to reflect a more common usage, for example,
what HP calls 'DNS_NAME' is referred to as 'hostname' by Net::ILO.

Boolean types are represented in the documentation as either 'Yes' or 'No'.
When ILO returns a boolean response, it is shortened to 'Y' or 'N'. Either form
is acceptable when passing a value to your server's iLO.

Power and UID statuses are an exception; their states can be either
'on' or 'off'.

=head1 METHODS

The interface is extensive and methods have been grouped by function for
easier digestion.

=head2 GENERAL METHODS

=over

=item new()

    my $ilo = Net::ILO->new({
        address     => '192.168.131.185',
        username    => 'Administrator',
        password    => 'secret',
    });

    # can also use a hash rather than hashref

    my $ilo = Net::ILO->new(
        address     => '192.168.131.185',
        username    => 'Administrator',
        password    => 'secret',
    );

Creates a new ILO object, but does not attempt a connection. Parameters
are passed as an anonymous hash or hashref.

Required paramters:

None, however trying to call any method without setting at least the
address, username and password will fail. You may however, set these
later using their associated methods if you want.

Optional parameters:

  address - hostname or IP of remote machine's iLO
     port - default is 443, you may specify another port here
 username - username for logging in to iLO
 password - password for logging in to iLO
  version - version of iLO API to use, '1', '2' or '3'. versions 1 and 2 are
            the same and correspond to iLO and iLO 2 respectively, if version
            '3' is used the module will use the new iLO 3 interface. if not
            specified the version will be detected automatically (recommended)
    debug - debug level (default 0). Increasing this number (to a maximum of 3)
            displays more diagnostic information to the screen, such as the
            data sent to and received from iLO, the Perl data structure
            created from the XML received, etc.

=item address()

    # connect to a different machine
    $ilo->address('192.168.131.186');

    print $ilo->power;

Returns or sets the address of the remote machine to connect to.

Please note that a lot of the data gathered (power state excluded) is cached.
Connecting to machine A, calling mac01(), then connecting to machine B and
calling mac01() will return the same data. It is recommended that you
instantiate a new object for each server you connect to.

=item port()

    # your company's machines use a non-standard SSL port
    $ilo->port(447);

Returns or sets the port to connect to the remote server on.
Port 443 is assumed if not specified.

=item username()

    $ilo->username('jane_doe');

    # do some non-admin tasks
    # power-cycling machine requires elevated privileges

    $ilo->username('Administrator');
    $ilo->power('reset');

Returns or sets the username to use when logging in.

=item password()

    # try both passwords, we forgot which one was good
    $ilo->password('foobar');

    # all methods return false on failure
    if (!$ilo->power) {

        $ilo->password('barfoo');

    }

Returns or sets the password to use when logging in.

=item error()

    $ilo->address('127.0.0.1');

    my $power_status = $ilo->power or die $ilo->error;

    Unable to establish SSL connection with 127.0.0.1:443
    [IO::Socket::INET6 configuration failederror:00000000:lib(0):func(0):reason(0)] at /somescript.pl line 14.

Returns the last error reported, if any. All methods return false when
an error is encountered, and $ilo->error is set to the error message
reported by the remote machine. Note that on success, error() is not cleared,
and so should not be used to determine whether an error occurred.

Every single method which interacts with the remote machine may throw an
error, so it is very important that you check to ensure the command
succeeded. Error checking has been omitted from most examples for brevity.

=back

=head2 POWER MANAGEMENT

=over

=item power()

    my $power_status = $ilo->power;

    if ($power_status eq 'off') {

        $ilo->power('on');

    }
    else {

        $ilo->power('reset');

    }

Calling this method without parameters will return the current power
state of the machine, either 'on' or 'off'. Passing any of the following
to this method will attempt to change the power state:

    on
    off
    reset

=item power_consumption()

    # something like 340
    print $ilo->power_consumption;

Returns the current power consumption in watts.

This method is only available when using iLO 2 and above. Calling it on an
older machine will cause the following error to be returned:

Method not supported by this iLO version

=back

=head2 NETWORKING

=over

=item hostname

    # default is ILO0000000000 where 000... is your serial number
    my $machine_name = $ilo->hostname;

Returns the hostname of the iLO processor. This is also the name shown
when logging in to the iLO interface, in the SSL cert, etc.

For information on changing the hostname, see the network() method.

=item domain_name()

    # maybe ilo.somecompany.net
    my $domain_name = $ilo->domain_name;

Returns the DNS domain name of the iLO processor.

For information on changing the domain name, see the network() method.

=item dhcp_enabled()

    # either 'Y' or 'N'
    print $ilo->dhcp_enabled;

Returns 'Y' if DHCP is enabled for the iLO networking, and 'N' if a
static IP address is in use.

=item ip_address()

    # network dependent, something like 192.168.1.129
    print $ilo->ip_address;

Returns the IP address of the iLO processor. Note that the IP can NOT
be changed using this method. For managing network settings, see
network().

=item subnet_mask()

    # network dependent, something like 255.255.255.0
    print $ilo->subnet_mask;

Returns the subnet mask of the iLO processor.

=item gateway()

    # you guessed it, network dependent
    print $ilo->gateway;

Returns the default gateway in use for the iLO networking.

=item speed_autoselect()

    # either 'Y' or 'N'
    print $ilo->speed_autoselect;

'Y' if iLO will autonegotiate port speed.

=item ping_gateway()

    # either 'Y' or 'N'
    print $ilo->ping_gateway;

"Y" if iLO is to ping the gateway address on boot.

=item gratuitous_arp()

    # either 'Y' or 'N'
    print $ilo->gratuitous_arp;

"Y" if iLO is to perform a gratuitous arp on boot.

=item dhcp_gateway()

    # either 'Y' or 'N'
    print $ilo->dhcp_gateway;

Returns "Y" if iLO is to get the default gateway from the DHCP server,
"N" if static information are used.

=item dhcp_dns_server()

    # either 'Y' or 'N'
    print $ilo->dhcp_sntp_settings;

Returns "Y" if iLO is to get the DNS servers from the DHCP server,
"N" if static information are used.

=item prim_dns_server(), sec_dns_server(), ter_dns_server()

    # the IP address of the first DNS server
    print $ilo->prim_dns_server;

Return the IP address of the primary, secondary or tertiary DNS server,
respectively.

=item reg_ddns_server()

    # either 'Y' or 'N'
    print $ilo->reg_ddns_server;

"Y" if iLO will attempt to register with the dns server.

=item reg_wins_server()

    # either 'Y' or 'N'
    print $ilo->reg_wins_server;

"Y" if iLO will attempt to register with the wins server.

=item dhcp_sntp_settings()

    # either 'Y' or 'N'
    print $ilo->dhcp_sntp_settings;

Returns "Y" if iLO is to get the SNTP time servers and timezone from
the DHCP server, "N" if static information are used.

=item sntp_server1(), sntp_server2()

    # the IP address of the first SNTP server
    print $ilo->sntp_server1;

Returns the IP address of the corresponding SNTP server.

=item timezone()

    # the timezone, e.g. "Europe/Paris"
    print $ilo->timezone;

Returns the timezone.

=item network()

    $ilo->network({
        hostname        => 'testbox01',
        domain_name     => 'mydomain.com',
        dhcp_enabled    => 'no',
        ip_address      => '192.168.128.10',
        subnet_mask     => '255.255.255.0',
        gateway         => '192.168.128.1',
    }) or die $ilo->error;

Allows you to modify the network configuration of the iLO processor. The
following parameters are allowed, see individual methods above for more detail:

    hostname
    domain_name
    dhcp_enabled
    ip_address
    subnet_mask
    gateway
    dhcp_gateway
    dhcp_dns_server
    prim_dns_server
    sec_dns_server
    ter_dns_server
    reg_ddns_server
    reg_wins_server
    dhcp_sntp_settings
    sntp_server1
    sntp_server2
    timezone

If any parameter is not specified, current values are used.

Setting dhcp_enabled to 'yes' causes all IP related settings to have no effect.

If the IP address is changed here, address() is updated with the new information.

Networking changes cause the iLO processor to reset, it should become
available again within 30 seconds.

The rationale behind seperate methods for viewing and changing network
settings is as follows:

Network configuration generally needs to be modified as a package, for
example, changing both the IP address and default gateway. Without a
separate method, calling the ip_address() method as a setter could
cause you to lose connectivity.

=back

=head2 SYSTEM INFORMATION

=over

=item model()

    # ProLiant DL380 G5
    print $ilo->model;

Returns the model name of the machine.

=item server_name()

    # an unconfigured iLO will return a name based on the product
    # number of the server, for example: DL365G1POA00
    print $ilo->server_name;

    # set the server name
    $ilo->server_name("room04.aperturescience.com");

Get or set the name of the server as it is known to iLO. This value
is not forwarded to the host operating system, and therefore need not
be a valid DNS compatible name.

=item serial_cli_speed()

    $ilo->serial_cli_speed(2);  # set the CLI port speed to 19,200 bps

Get or set the speed of the CLI port speed. The possible values are:
0 (no change), 1 (9,600 bps), 2 (19,200 bps), 3 (38,400 bps),
4 (57,600 bps), 5 (115,200 bps).

=item serial_cli_status()

    # print the status of the CLI
    print $ilo->serial_cli_status;

Get or set the status of the CLI. The possible values are: 0 (no change),
1 (disabled), 2 (enabled, no authentication required), 3 (enabled,
authentication required).

=item serialID()

    # unique to your machine
    print $ilo->serialID;

Returns the serial number of the remote machine.

=item cpus()

    my $cpus = $ilo->cpus;

    print "Number of CPUs: ", scalar @$cpus, "\n\n";

    foreach my $cpu (@$cpus) {

        print "  CPU: ", $cpu->{name}, "\n";
        print "Speed: ", $cpu->{speed}, "\n";
        print "Cores: ", $cpu->{cores}, "\n";

    }

    # yields the following on a single CPU Xeon:
    #
    # Number of CPUs: 1
    #
    #   CPU: Proc 1
    # Speed: 2000 MHz
    # Cores: 4 of 4 cores; 4 threads

Returns arrayref containing information about each CPU. Included is the
CPU name (eg. Proc 1, Proc 2, etc.), speed in MHz and number of cores.

=item ramslots()

    my $ramslots = $ilo->ramslots or die $ilo->error;

    print "DIMM slots: ", scalar @$ramslots, "\n\n";

    foreach my $slot (@$ramslots) {

        print " Slot: ", $slot->{location}, "\n";
        print " Size: ", $slot->{size},     "\n";
        print "Speed: ", $slot->{speed},    "\n" if defined $slot->{speed};

    }

    # yields the following on a DL360/G5 with 8 GB of RAM:
    #
    # DIMM slots: 8
    #
    # Slot: DIMM 1A
    # Size: 2048 MB
    # Speed: 667 MHz
    #
    # Slot: DIMM 2C
    # Size: 1024 MB
    # Speed: 667 MHz
    #
    # Slot: DIMM 3A
    # Size: 2048 MB
    # Speed: 667 MHz
    #
    # Slot: DIMM 4C
    # Size: 1024 MB
    # Speed: 667 MHz
    #
    # Slot: DIMM 5B
    # Size: 1024 MB
    # Speed: 667 MHz
    #
    # Slot: DIMM 6D
    # Size: not installed
    #
    # Slot: DIMM 7B
    # Size: 1024 MB
    # Speed: 667 MHz
    #
    # Slot: DIMM 8D
    # Size: not installed

Returns arrayref containing information about installed memory modules. Includes
slot name, module size and module speed. Speed is undefined when slot is empty.

=item mac01()

    my $eth0_mac = $ilo->mac01;

Returns the mac address associated with the machine's primary NIC (aka eth0).

This method is not supported by pre-generation 4 hardware.

=item mac02()

    my $eth1_mac = $ilo->mac02;

Returns the mac address associated with the machine's secondary NIC (aka eth1).

This method is not supported by pre-generation 4 hardware.

=item mac03()

    my $eth2_mac = $ilo->mac03;

Returns the mac address associated with the machine's tertiary NIC, if
installed. Note that mac addresses for add-on cards will not be available
via this method.

=item mac04()

    my $eth3_mac = $ilo->mac04;

Returns the mac address associated with the machine's quaternary NIC, if
installed. Note that mac addresses for add-on cards will not be available
via this method.

=item macilo()

    my $ilo_mac = $ilo->macilo;

Returns the mac address associated with the machine's iLO interface.

This method is not supported by pre-generation 4 hardware.

=item biosdate()

    # format is 11/30/2006
    print $ilo->biosdate;

Returns the release date of the system's BIOS.

=back

=head2 SERVER HEALTH

=over

=item fans()

    my $fans = $ilo->fans;

    foreach my $fan (@$fans) {

        print "    Name: ", $fan->{name},     "\n";
        print "Location: ", $fan->{location}, "\n";
        print "   Speed: ", $fan->{speed},    "\n";
        print "    Unit: ", $fan->{unit},     "\n";
        print "  Status: ", $fan->{status},   "\n\n";

    }

    #     Name: Fan Block 1
    # Location: Power Supply
    #    Speed: 34
    #     Unit: Percentage
    #   Status: Ok
    #
    #     Name: Fan Block 2
    # Location: CPU 2
    #    Speed: 29
    #     Unit: Percentage
    #   Status: Ok
    #
    #     Name: Fan Block 3
    # Location: CPU 1
    #    Speed: 34
    #     Unit: Percentage
    #   Status: Ok

Returns arrayref containing the status of the fan block(s) installed in the
system. 'status' will be 'Ok' or 'Failed'.

=item temperatures()

    my $temperatures = $ilo->temperatures;

    foreach my $sensor (@$temperatures) {

        print "    Name: ", $sensor->{name},     "\n";
        print "Location: ", $sensor->{location}, "\n";
        print "   Value: ", $sensor->{value},    "\n";
        print "    Unit: ", $sensor->{unit},     "\n";
        print " Caution: ", $sensor->{caution},  "\n";
        print "Critical: ", $sensor->{critical}, "\n";
        print "  Status: ", $sensor->{status},   "\n\n";

    }

    #     Name: Temp 1
    # Location: I/O Board
    #    Value: 49
    #     Unit: Celsius
    #  Caution: 80
    # Critical: 90
    #   Status: Ok
    #
    #     Name: Temp 2
    # Location: Ambient
    #    Value: 19
    #     Unit: Celsius
    #  Caution: 80
    # Critical: 90
    #   Status: Ok
    #
    #     Name: Temp 3
    # Location: CPU 1
    #    Value: 32
    #     Unit: Celsius
    #  Caution: 80
    # Critical: 90
    #   Status: Ok
    #
    #     Name: Temp 4
    # Location: CPU 1
    #    Value: 32
    #     Unit: Celsius
    #  Caution: 80
    # Critical: 90
    #   Status: Ok
    #
    #     Name: Temp 5
    # Location: Power Supply
    #    Value: 28
    #     Unit: Celsius
    #  Caution: 80
    # Critical: 90
    #   Status: Ok

Returns arrayref containing the status of the temperature sensor(s) installed
in the system. 'status' will be 'Failed' if the temperature exceeds the
critical threshold.

=item power_supplies()

    my $power_supplies = $ilo->power_supplies;

    foreach my $power_supply (@$power_supplies) {

        print "  Name: ", $power_supply->{name},   "\n";
        print "Status: ", $power_supply->{status}, "\n\n";

    }

    #   Name: Power Supply 1
    # Status: Ok

Returns arrayref containing the status of the power supplies installed in the
system. 'status' will be 'Ok' or 'Failed'.

=back

=head2 ILO INFORMATION AND MANAGEMENT

=over

=item reset()

    # iLO web interface is hung, try resetting it
    $ilo->reset;

Resets the iLO management processor.

=item license()

    # 25 characters, according to HP
    $ilo->license('1111122222333334444455555');

Activates iLO advanced pack licensing. An error will be returned if
the key is not valid or if it is already in use.

=item fw_type()

    # either 'iLO', 'iLO2' or 'iLO3'
    print $ilo->fw_type;

Returns the type of iLO management processor in the remote machine.
Possible values are 'iLO', 'iLO2' and 'iLO3', depending on
how modern the server is.

=item fw_version()

    # something like 1.26
    print $ilo->fw_version;

Returns the version of iLO firmware currently running.

=item fw_date()

    # format is Nov 17 2006
    print $ilo->fw_date;

Returns the date the iLO firmware was released.

=item ssh_status()

    # either 'Y' or 'N'
    print $ilo->ssh_status;

    # disable SSH access to iLO
    $ilo->ssh_status('No');

Returns or modifies whether SSH access is enabled on the iLO.
Gives 'Y' if SSH is enabled and 'N' if SSH is disabled.

=item ssh_port()

    if ($ilo->ssh_port == 22) {

        $ilo->ssh_port(12345);

    }

Returns or sets the port iLO will listen on for incoming SSH connections.
This should be an integer between 0 and 65535.

Changing the SSH port causes the iLO processor to reset, it should become
available again within about 30 seconds.

=item http_port()

    # default is 80
    print $ilo->http_port;

    $ilo->http_port(8000);

Returns or sets the port iLO's http service listens on. Valid port numbers
are between 0 and 65535.

Changing the HTTP port causes the iLO processor to reset, it should become
available again within about 30 seconds.

=item https_port()

    # default is 443
    print $ilo->https_port;

    $ilo->https_port(554);

Returns or sets the port iLO's https service listens on. Valid port numbers
are between 0 and 65535.

Changing the HTTPS port causes the iLO processor to reset, it should become
available again within about 30 seconds.

=item session_timeout()

    # default is 30
    print $ilo->session_timeout;

Returns the current session timeout in minutes. This applies to all sessions,
eg. http, https, ssh, etc.

=back

=head2 USER MANAGEMENT

=over

=item add_user()

    # add a user with admin privileges
    $ilo->add_user({
        name     => 'John Doe',
        username => 'jdoe',
        password => 'secret',
        admin    => 'Yes',
    });

    # add a regular user with no privileges
    $ilo->add_user({
        name     => 'Jim Beam',
        username => 'jbeam',
        password => 'secret',
    });

    # add a regular user with full privileges (aside from managing users)
    #
    # for a detailed discussion of what each privilege provides, please see
    # the document 'HP Integrated Lights-Out Management Processor Scripting and
    # Command Line Resource Guide'
    #
    # if unspecified, default for each privilege is 'No'.

    $ilo->add_user({
        name     => 'Jack Daniels',
        username => 'jdaniels',
        password => 'secret',
        remote_console_privilege => 'Yes',
        reset_privilege          => 'Yes',
        virtual_media_privilege  => 'Yes',
        config_ilo_privilege     => 'Yes',
        view_logs_privilege      => 'Yes',
        clear_logs_privilege     => 'Yes',
        update_ilo_privilege     => 'Yes',
    })

Adds an iLO user. Admin users have full privileges, including the ability to
add and remove other users. Non-admin users have configurable privileges which
default to disabled. The subset of permissions implemented is listed above.
Users can log in to iLO via any interface, ie. HTTPS, SSH, etc. When adding a
non-admin user, passing in the parameter admin => 'No' is also acceptable.


=item get_user()

    my $user_info = $ilo->get_user("cjohnson");

    my @privileges = grep { $user_info->{$_} =~ /^Y/ } qw<
        admin  remote_console_privilege  reset_privilege
        virtual_media_privilege  config_ilo_privilege
    >;

    s/_privilege$// for @privileges;

    print "user name: $user_info->{name}\n",
          "     privileges: @privileges\n";

    # user name: Cave Johnson
    #      privileges: admin remote_console reset virtual_media config_ilo

Method for fetching information about a user account. Returns a hashref
with mostly the same fields than the ones you pass to C<add_user()>:
C<name>, C<username>, C<admin>, C<remote_console_privilege>,
C<reset_privilege>, C<virtual_media_privilege>, C<config_ilo_privilege>.


=item mod_user()

    # change current user's password
    # in this case username is optional

    $ilo->mod_user({
        password => 'supersecret',
    });

    # change another user's password
    # this requires administrator privileges

    $ilo->mod_user({
        username => 'guest',
        password => 'changem3!',
    });

Method for modifying existing user accounts. Currently this method is
only able to change user's passwords; it cannot change permission
levels.

Passwords may consist of up to 39 printable characters. If you exceed
the maximum password length, an error to that effect will be returned.

If you update the current user's password the stored password used for
logging in will be updated automatically.

=item del_user()

    # you're fired!
    $ilo->del_user('jbeam');

Removes an existing user from the iLO.

=back

=head2 MISCELLANEOUS

=over

=item uid()

    if ($ilo->uid eq 'on') {

        $ilo->uid('off');

    }

Get the status of or control the machine's UID light.

Called without parameters simply returns the current status, either
'on' or 'off'.

You may pass values 'on' or 'off' to this method however be careful not to
set the uid light to on when it is currently on, and vice versa, as this
could throw an error, depending on iLO firmware version.

An error will be returned if you pass an invalid state.

    $ilo->uid('blinking') or die $ilo->error;

    State blinking is not valid at /somescript.pl line 13.

=back

=head1 DIAGNOSTICS

=over

=item C<User login name was not found>

General authentication error, eg. bad username or password when logging in.

Could also mean you attempted to change the settings (eg. password) for a
user which doesn't exist

=item C<Method not supported by this iLO version>

Either your machine / iLO firmware version is too old, or the method you called
requires a more advanced license than you have.

=item C<State %s is not valid>

An invalid UID state was passed to uid(). Valid states are 'on' and 'off'.

=item C<Unable to establish SSL connection with %s:%d [%s]>

An error occurred while connecting to iLO. The message in brackets is
propagated from IO::Socket::SSL, and is rarely useful.

=item C<Error transmitting command to server>

A connection was established, but something went wrong while sending the
command to the remote iLO. Try reconnecting, and ensure that your
network settings are correct.

=item C<No response received from remote machine>

A connection was established and a command successfully sent to the iLO, but
no data was received. Again, ensure that your network settings are correct.

There could also be something wrong with the remote iLO management processor.
Troubleshooting is beyond the scope of this document.

=item C<Error parsing response: %s>

An error occurred while parsing the XML response from the iLO. The error
message is propagated from XML::Simple, and could mean HP changed the iLO
API.

=back

=head1 DEPENDENCIES

    IO::Socket::SSL
    XML::Simple

=head1 AUTHOR

Nicholas Lewis, C<< <nick.lewis at gmail.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-ilo at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-ILO>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::ILO


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-ILO>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-ILO>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-ILO>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-ILO>

=back


=head1 COPYRIGHT & LICENSE

Copyright 2011 Nicholas Lewis, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.


=cut

