# Test successful loading of Net::Traces::TSH
#
use strict;
use Test;

BEGIN { plan tests => 1 };
use Net::Traces::TSH 0.05;
ok(1);