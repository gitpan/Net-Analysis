# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net::Analysis-Utils.t'

use strict;
use Data::Dumper;
use Test::More tests => 7;
use t::TestMockListener;

use Net::Analysis::Dispatcher;

#########################

BEGIN { use_ok('Net::Analysis::EventLoop') };

#### Make a dispatcher, and some mocked up listeners.
#
my ($d) = Net::Analysis::Dispatcher->new();
isnt ($d, undef, "new dispatcher");

my ($mock_listener_pkt) = mock_listener(qw(tcp_packet));
my ($mock_listener_scf) = mock_listener(qw(setup teardown));

$d->add_listener (listener => $mock_listener_pkt);
$d->add_listener (listener => $mock_listener_scf);


#### Call the event_loop, and see what events our mocked object received
#
my ($el) = Net::Analysis::EventLoop->new (dispatcher => $d);
isnt ($el, undef, "EventLoop->new()");

$el->loop_file (filename => 't/t1_google.tcp');

my (@calls, $event_name, @args, $pkt);

#### Check for scaffold events from event_loop
#
while (($event_name, @args) = $mock_listener_scf->next_call()) {
    push (@calls, $event_name);
}
is_deeply (\@calls, ['setup', 'teardown'], "scaffold events present");
@calls = ();

#### Check for the packet events
#
while (($event_name, @args) = $mock_listener_pkt->next_call()) {
    next if ($event_name ne 'tcp_packet');
    $pkt = $args[0][1]{pkt};
    #die Data::Dumper::Dumper ($pkt);
    my $str = "$pkt->{from}-$pkt->{to},S$pkt->{seqnum},A$pkt->{acknum}";
    #print "$str\n"; # Help to generate thing below.
    push (@calls, $str);
}

# Note; 'tv' should be .792253, but the default format for floats rounds the
#  last digit.

my $dumped_packet = <<'EO';
$VAR1 = bless( {
                 'pkt_number' => 10,
                 'flags' => 16,
                 'time' => bless( {
                                    'us' => 792253,
                                    's' => 1096989582
                                  }, 'Net::Analysis::Time' ),
                 'seqnum' => 167069663,
                 'data' => '',
                 'socketpair_key' => '145.246.233.194:33403-216.239.59.147:80',
                 'to' => '216.239.59.147:80',
                 'from' => '145.246.233.194:33403',
                 'acknum' => 2087077847,
                 'class' => 0
               }, 'Net::Analysis::Packet' );
EO
is (Dumper ($pkt), $dumped_packet, "last packet is well formed");

is (scalar(@calls), 11, "read 11 tcp_packet events");

is_deeply (\@calls,
           ['145.246.233.194:33403-216.239.59.147:80,S167069550,A0',
            '216.239.59.147:80-145.246.233.194:33403,S2087075600,A167069551',
            '145.246.233.194:33403-216.239.59.147:80,S167069551,A2087075601',
            '145.246.233.194:33403-216.239.59.147:80,S167069551,A2087075601',
            '216.239.59.147:80-145.246.233.194:33403,S2087075601,A167069662',
            '145.246.233.194:33403-216.239.59.147:80,S167069662,A2087076969',
            '216.239.59.147:80-145.246.233.194:33403,S2087076969,A167069662',
            '145.246.233.194:33403-216.239.59.147:80,S167069662,A2087077846',
            '145.246.233.194:33403-216.239.59.147:80,S167069662,A2087077846',
            '216.239.59.147:80-145.246.233.194:33403,S2087077846,A167069663',
            '145.246.233.194:33403-216.239.59.147:80,S167069663,A2087077847'],
           "tcp_packet events all present");

# End
