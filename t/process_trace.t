# Test correct operation of Net::Traces::TSH process_trace()
#
use strict;
use Test;

BEGIN { plan tests => 31};
use Net::Traces::TSH 0.07 qw( process_trace get_trace_summary_href);
ok(1);

process_trace 't/sample.tsh';
ok(1);

my $trace_href = get_trace_summary_href;
ok(1);

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
ok($trace_href->{IP}{'Normal Packets'}, 1000);
ok($trace_href->{IP}{'No IP Options Packets'}, 1000);

ok($trace_href->{Transport}{TCP}{'Total ACKs'}, 576);
ok($trace_href->{Transport}{TCP}{'Cumulative ACKs'}, 506);
ok($trace_href->{Transport}{TCP}{'Pure ACKs'}, 151);
ok($trace_href->{Transport}{TCP}{'Options ACKs'}, 70);

ok($trace_href->{Transport}{TCP}{'DF Bytes'}, 325_656);
ok($trace_href->{Transport}{TCP}{'ECT Bytes'}, undef);

ok($trace_href->{Transport}{UDP}{'Normal Bytes'}, 28198);
ok($trace_href->{Transport}{UDP}{'DF Bytes'}, 14096);

ok($trace_href->{Transport}{ICMP}{'Total Bytes'}, 1700);
ok($trace_href->{Transport}{ICMP}{'DF Packets'}, 6);
ok($trace_href->{Transport}{ICMP}{'DF Bytes'}, 336);

ok($trace_href->{Transport}{Unknown}{'Total Bytes'}, 216);
ok($trace_href->{Transport}{Unknown}{'Total Packets'}, 3);

if ( $^O =~ m/MSWin/ ) {
  skip "Skipping context diff between distribution ", "";
  skip "t/sample.tcpdump and locally generated t/local.tcpdump", "";
}
else {
  my $diff_avail = 0;

  eval {
    $diff_avail = system('diff', 't/sample.tcpdump', 't/sample.tcpdump');
  };

  skip ( $diff_avail >> 8, 
         ok(system('diff', 't/local.tcpdump', 't/sample.tcpdump'), 0)
       );
}

unlink('t/local.tcpdump');
ok(1);