# Test correct operation of Net::Traces::TSH records_in()
#
use strict;
use Test;

BEGIN { plan tests => 2 };
use Net::Traces::TSH 0.08 qw( records_in );
ok(1);

ok(records_in 't/sample.tsh', 1000);