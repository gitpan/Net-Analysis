package Net::Analysis::Packet;
# $Id: Packet.pm 131 2005-10-02 17:24:31Z abworrall $

use 5.008000;
our $VERSION = '0.01';
use strict;
use warnings;
use Carp qw(carp);
use POSIX qw(strftime);
use overload
    q("") => sub { $_[0]->as_string() },
    'eq'  => sub { return "$_[0]" eq "$_[1]" }; # Needed for Test::is_deeply

use Net::Analysis::Constants qw(:tcpflags :packetclasses);
use Net::Analysis::Time;

#### Public methods
#
# {{{ new

sub new {
    my ($class, $pkt_data) = @_;

    if (!defined $pkt_data) {
        carp ('Net::Analysis::Packet->new($pkt_data) not given $pkt_data!');
        return undef;
    }

    my %h = %$pkt_data;

    my ($self)  = bless (\%h, $class);

    # Setup a time object
    if (!exists $self->{time}) {
        if (exists $self->{tv}) {
            $self->{time} = Net::Analysis::Time->new ($self->{tv});
            delete ($self->{tv});

        } elsif (exists $self->{tv_sec} && exists $self->{tv_usec}) {
            $self->{time} = Net::Analysis::Time->new ($self->{tv_sec},
                                                      $self->{tv_usec});
            delete ($self->{tv_sec});
            delete ($self->{tv_usec});

        } else {
            carp "Net::Analysis::Packet->new(); no time, tv, or tv_sec/tv_usec\n";
            $self->{time} = Net::Analysis::Time->new (0, 666);
        }
    }
    $self->{socketpair_key} = join('-', sort ($self->{from}, $self->{to}));

    $self->{class} = PKT_NOCLASS;

    return $self;
}

# }}}

# {{{ class

sub class {
    my ($self, $new) = @_;

    $self->{class} = $new if (defined $new);

    return $self->{class};
}

# }}}
# {{{ socketpair

sub socketpair { return $_[0]->{socketpair_key} };

# }}}
# {{{ as_string

sub as_string {
    my ($self, $v) = @_;

    carp "bad pkt !\n" if (!exists $self->{pkt_number});

    my $flags = '';
    $flags .= 'F' if ($self->{flags} & FIN);
    $flags .= 'S' if ($self->{flags} & SYN);
    $flags .= 'A' if ($self->{flags} & ACK);
    $flags .= 'R' if ($self->{flags} & RST);
    $flags .= 'P' if ($self->{flags} & PSH);
    $flags .= 'U' if ($self->{flags} & URG);
    $flags .= '.' if ($flags eq '');

    my $time = ($self->{time}) ? $self->{time}->as_string('time') : "--";

    my $str = sprintf ("(% 3d $time %s-%s) ",
                       $self->{pkt_number}, $self->{from}, $self->{to});

    # Show which class we have assigned to the packet
    $str .= {PKT_NOCLASS,     '-',
             PKT_NONDATA,     '_',
             PKT_DATA,        '*',
             PKT_DUP_DATA,    'p',
             PKT_FUTURE_DATA, 'f'}->{$self->{class}} || '?';

    $str .= sprintf ("%-6s ", "$flags");

    $str .= "SEQ:$self->{seqnum} ACK:$self->{acknum} ".
      length($self->{data})."b";

    if ($v) { # Get all verbose
        $str .= "\n"._hex_dump ($self->{data});
    }

    return $str;
}

# }}}

#### Private helpers
#
# {{{ _hex_dump

sub _hex_dump {
    my ($binary, $prefix) = @_;

    $prefix ||= '';
    my $hex = $prefix.unpack("H*", $binary);

    $hex =~ s {([0-9a-f]{2}(?! ))}     { $1}mg;

    $hex =~ s {(( [0-9a-f]{2}){16})}
              {"$1   ".safe_raw_line($1)."\n"}emg;

    # Unfinished last line
    $hex =~ s {(( [0-9a-f]{2})*)$}
              {sprintf("%-47.47s    ",$1) .safe_raw_line($1)."\n"}es;

    chomp($hex);
    return $hex."\n";
}

sub safe_raw_line {
    my ($s) = @_;
    $s =~ s {\s+} {}mg;

    my $raw = pack("H*", $s);
    $raw =~ s {([^\x20-\x7e])} {.}g;
    return "{$raw}";
}

# }}}


1;
__END__
# {{{ POD

=head1 NAME

Net::Analysis::Packet - wrapper for our own view of a packet.

=head1 SYNOPSIS

  use Net::Analysis::Packet;

  my $p = Net::Analysis::Packet ( {...} ); # See Net::Analysis::EventLoop

  print "My packet:-\n$p";

=head1 DESCRIPTION

Internal module for abstracting the underlying packet representation.

=head2 EXPORT

None by default.

=head1 SEE ALSO

Net::Analysis::EventLoop - creates these packets

=head1 AUTHOR

Adam B. Worrall, E<lt>worrall@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Adam B. Worrall

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.5 or,
at your option, any later version of Perl 5 you may have available.


=cut

# }}}

# {{{ -------------------------={ E N D }=----------------------------------

# Local variables:
# folded-file: t
# end:

# }}}
