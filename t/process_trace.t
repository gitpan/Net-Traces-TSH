# Test correct operation of Net::Traces::TSH process_trace()
#
use strict;
use Test;

BEGIN { plan tests => 17 };
use Net::Traces::TSH 0.04 qw( process_trace get_trace_summary_href);
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

process_trace 't/sample.tsh', undef, 't/local.tcpdump';
ok(1);

ok($trace_href->{IP}{'Total Packets'}, 1000);
ok($trace_href->{Transport}{TCP}{'Total ACKs'}, 576);
ok($trace_href->{Transport}{UDP}{'Total Bytes'}, 28_198);

my $unless_has_diff = system('diff', 't/sample.tcpdump', 't/sample.tcpdump');

skip ( $unless_has_diff,
       ok(system('diff', 't/local.tcpdump', 't/sample.tcpdump'), 0) );

unlink('local.tcpdump');
ok(1)
