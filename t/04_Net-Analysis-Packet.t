# $ cd Net-Analysis
# $ make test                        # Run all test files
# $ PERL5LIB=./lib perl t/00_stub.t  # Run just this test suite

# $Id$

use strict;
use warnings;
use Data::Dumper;

use Test::More tests => 7;

#########################

BEGIN { use_ok('Net::Analysis::Packet') };

use Net::Analysis::Constants qw(:packetclasses);

my $data =
  { to => "1.2.3.4:80",
    from => "10.0.0.1:1024",
    flags => 0x12,
    data => 'some nice sample data',
    tv_sec => 1097432695,
    tv_usec => 123456,
    seqnum => 23,
    acknum => 24,
    pkt_number => 666,
  };

my $pkt = Net::Analysis::Packet->new($data);
isnt ($pkt, undef, "created packet");

like ($pkt->socketpair(), qr/$data->{from}/, "socketpair correct");

my $str1 = "( 666 18:24:55.123456 10.0.0.1:1024-1.2.3.4:80) -SA     SEQ:23 ACK:24 21b";
my $str2 =<<EO;
( 666 18:24:55.123456 10.0.0.1:1024-1.2.3.4:80) -SA     SEQ:23 ACK:24 21b
 73 6f 6d 65 20 6e 69 63 65 20 73 61 6d 70 6c 65   {some nice sample}
 20 64 61 74 61                                    { data}
EO

is ("$pkt", $str1, "as_string");
is ($pkt->as_string(1), $str2, "as_string(verbose)");

$str1 =~ s/-SA/*SA/; # Change the expected output to a known class
is ($pkt->class(PKT_DATA), PKT_DATA, "->class(PKT_DATA)");
is ("$pkt", $str1, "as_string summary after class");

__END__
