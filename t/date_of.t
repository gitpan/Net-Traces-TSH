# Test correct operation of Net::Traces::TSH date_of()
#
use strict;
use Test;

BEGIN { plan tests => 5 };
use Net::Traces::TSH 0.06 qw( date_of );
ok(1);

ok(date_of 'AIX-1072917725-1.csv', 'Thu Jan  1 00:42:05 2004 GMT');
ok(date_of 'BWY-1068001821-1.csv', 'Wed Nov  5 03:10:21 2003 GMT');
ok(date_of 'ODU-1073132115.tsh', 'Sat Jan  3 12:15:15 2004 GMT');
ok(date_of 'sample.tsh', '');