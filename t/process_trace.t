# Test correct operation of Net::Traces::TSH date_of()
#
use strict;
use Test;

BEGIN { plan tests => 10 };
use Net::Traces::TSH 0.03 qw( process_trace get_trace_summary_href);
ok(1);

process_trace 't/sample.tsh';
ok(1);

my $trace_href = get_trace_summary_href;

ok($trace_href->{filename}, 't/sample.tsh');

ok($trace_href->{IP}{'Total Packets'}, 1000);
ok($trace_href->{IP}{'Total Bytes'}, 356_422);

ok($trace_href->{Transport}{TCP}{'Total Packets'}, 842);
ok($trace_href->{Transport}{TCP}{'Total ACKs'}, 576);
ok($trace_href->{Transport}{TCP}{'Total Bytes'}, 326_308);

ok($trace_href->{Transport}{UDP}{'Total Packets'}, 133);
ok($trace_href->{Transport}{UDP}{'Total Bytes'}, 28_198);