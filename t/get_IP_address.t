# Test correct operation of Net::Traces::TSH date_of()
#
use strict;
use Test;

BEGIN { plan tests => 5 };
use Net::Traces::TSH 0.02 qw( get_IP_address );

ok(get_IP_address 167772172, '10.0.0.12');
ok(get_IP_address 167772174, '10.0.0.14');
ok(get_IP_address 180781201, '10.198.128.145');
ok(get_IP_address 947876734, '56.127.115.126');
ok(get_IP_address 2614034432, '155.207.0.0');
