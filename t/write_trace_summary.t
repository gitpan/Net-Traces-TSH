# Test correct operation of Net::Traces::TSH process_trace()
#
use strict;
use Test;

BEGIN { plan tests => 6 };
use Net::Traces::TSH 0.06 qw( process_trace write_trace_summary);
ok(1);

process_trace 't/sample.tsh';
ok(1);

write_trace_summary;
ok(1);

eval { system('diff', 't/sample.csv', 't/sample.csv'); };

skip ( $@,
       ok(system('diff', 't/sample.tsh.csv', 't/sample.csv'), 0) );

unlink('t/sample.tsh.csv');
ok(1);

