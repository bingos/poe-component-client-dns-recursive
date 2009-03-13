package POE::Component::Client::DNS::Recursive;

use strict;
use warnings;
use Socket;
use Net::IP qw(:PROC);
use IO::Socket::INET;
use POE qw(NFA);
use Net::DNS::Packet;
use vars qw($VERSION);

$VERSION = '0.02';

my @hc_hints = qw(
198.41.0.4
192.58.128.30
192.112.36.4
202.12.27.33
192.5.5.241
128.63.2.53
192.36.148.17
192.33.4.12
192.228.79.201
199.7.83.42
128.8.10.90
193.0.14.129
192.203.230.10
);

sub resolve {
  my $package = shift;
  my %opts = @_;
  $opts{lc $_} = delete $opts{$_} for keys %opts;
  # Check for 'host'
  # Check for 'event'
  $opts{nameservers} = [ ] unless $opts{nameservers} and ref $opts{nameservers} eq 'ARRAY';
  @{ $opts{nameservers} } = grep { ip_get_version( $_ ) } @{ $opts{nameservers} };
  my $options = delete $opts{options};
  my $self = bless \%opts, $package;
  POE::NFA->spawn(
  inline_states => {
    initial => {
	_self  => sub { $_[RUNSTATE] = $self; $poe_kernel->yield( '_setup' ); return; },
        _setup => \&_start,
    },
    hints   => {
        _setup => \&_send,
        _read  => \&_hints,
        _timeout => \&_hints_timeout,
    },
    query   => {
        _setup => \&_send,
        _read  => \&_query,
        _timeout => \&_query_timeout,
    },
  },
  )->goto_state( 'initial' => '_self' );
  return $self;
}

sub _start {
  my ($machine,$runstate) = @_[MACHINE,RUNSTATE];
  my $type = $runstate->{type} || ( ip_get_version( $runstate->{host} ) ? 'PTR' : 'A' );
  my $class = $runstate->{class} || 'IN';
  $runstate->{qstack} = [ ];
  $runstate->{current} = {
        query => $runstate->{host},
        type  => $type,
        packet => Net::DNS::Packet->new($runstate->{host},$type,$class),
  };
  $runstate->{socket} = IO::Socket::INET->new( Proto => 'udp' );
  my $hints;
  if ( scalar @{ $runstate->{nameservers} } ) {
     $hints = $runstate->{nameservers};
  }
  else {
     $hints = \@hc_hints;
  }
  $runstate->{_hints} = $hints;
  $machine->goto_state( 'hints', '_setup', Net::DNS::Packet->new('.','NS','IN'), $hints->[rand $#{$hints}] );
  return;
}

sub _send {
  my ($machine,$runstate,$packet,$ns) = @_[MACHINE,RUNSTATE,ARG0,ARG1];
  my $socket = $runstate->{socket};
  my $data = $packet->data;
  my $server_address = pack_sockaddr_in( ( $runstate->{port} || 53 ), inet_aton($ns) );
  unless ( send( $socket, $data, 0, $server_address ) == length($data) ) {
     warn "$!\n";
     return;
  }
  $poe_kernel->select_read( $socket, '_read' );
  # Timeout
  $poe_kernel->delay( '_timeout', $runstate->{timeout} || 5 );
  return;
}

sub _hints {
  my ($machine,$runstate,$socket) = @_[MACHINE,RUNSTATE,ARG0];
  $poe_kernel->delay( '_timeout' );
  my $packet = _read_socket( $socket );
    my %hints;
    if (my @ans = $packet->answer) {
      foreach my $rr (@ans) {
        if ($rr->name =~ /^\.?$/ and
            $rr->type eq "NS") {
          # Found root authority
          my $server = lc $rr->rdatastr;
          $server =~ s/\.$//;
          $hints{$server} = [];
        }
      }
      foreach my $rr ($packet->additional) {
        if (my $server = lc $rr->name){
          if ( $rr->type eq "A") {
            if ($hints{$server}) {
              push @{ $hints{$server} }, $rr->rdatastr;
            }
          }
        }
      }
    }
    $runstate->{hints} = \%hints;
  my @ns = _ns_from_cache( $runstate->{hints} );
  my $query = $runstate->{current};
  $query->{servers} = \@ns;
  my ($nameserver) = splice @ns, rand($#ns), 1;
  $machine->goto_state( 'query', '_setup', $query->{packet}, $nameserver );
  return;
}

sub _hints_timeout {
  my ($machine,$runstate) = @_[MACHINE,RUNSTATE];
  my $hints = $runstate->{_hints};
  $machine->goto_state( 'hints', '_setup', Net::DNS::Packet->new('.','NS','IN'), $hints->[rand $#{$hints}] );
  return;
}

sub _query {
  my ($machine,$runstate,$socket) = @_[MACHINE,RUNSTATE,ARG0];
  $poe_kernel->delay( '_timeout' );
  my $packet = _read_socket( $socket );
  my @ns;
  my $status = $packet->header->rcode;
  print $packet->string, "\n";
  if ( $status ne 'NOERROR' ) {
        warn "$status\n";
        print $packet->string, "\n";
        return;
  }
  if (my @ans = $packet->answer) {
     # This is the end of the chain.
     unless ( scalar @{ $runstate->{qstack} } ) {
        warn "We have answers\n";
        print $packet->string, "\n";
        return;
     }
     # Okay we have queries pending.
     push @ns, $_->rdatastr for grep { $_->type eq 'A' } @ans;
     $runstate->{current} = pop @{ $runstate->{qstack} };
  }
  else {
     my $authority = _authority( $packet );
     @ns = _ns_from_cache( $authority );
     unless ( scalar @ns ) {
        $runstate->{current}->{authority} = $authority;
        push @{ $runstate->{qstack} }, $runstate->{current};
        my $host = ( keys %{ $authority } )[rand scalar keys %{ $authority }];
        delete $authority->{$host};
        $runstate->{current} = {
           query => $host,
           type  => 'A',
           packet => Net::DNS::Packet->new($host,'A','IN'),
        };
        @ns = _ns_from_cache( $runstate->{hints} );
     }
  }
  my $query = $runstate->{current};
  $query->{servers} = \@ns;
  my ($nameserver) = splice @ns, rand($#ns), 1;
  $poe_kernel->yield( '_setup', $query->{packet}, $nameserver );
  return;
}

sub _query_timeout {
  my ($machine,$runstate) = @_[MACHINE,RUNSTATE];
  my $query = $runstate->{current};
  my $servers = $query->{servers};
  my ($nameserver) = splice @{ $servers }, rand($#{ $servers }), 1;
  # actually check here if there is something on the stack.
  # pop off the most recent, and get the next authority record
  # push back on to the stack and do a lookup for the authority
  # record. No authority records left, then complain and bailout.
  unless ( $nameserver ) {
    if ( scalar @{ $runstate->{qstack} } ) {
        $runstate->{current} = pop @{ $runstate->{qstack} };
        my $host = ( keys %{ $runstate->{current}->{authority} } )[rand scalar keys %{ $runstate->{current}->{authority} }];
        return unless $host; # Oops
        delete $runstate->{current}->{authority}->{ $host };
        push @{ $runstate->{qstack} }, $runstate->{current};
        $runstate->{current} = {
           query => $host,
           type  => 'A',
           packet => Net::DNS::Packet->new($host,'A','IN'),
        };
        my @ns = _ns_from_cache( $runstate->{hints} );
        $runstate->{current}->{servers} = \@ns;
        ($nameserver) = splice @ns, rand($#ns), 1;
    }
    else {
        return; # OMG
    }
  }
  return unless $nameserver; # SERVFAIL? maybe
  $poe_kernel->yield( '_setup', $query->{packet}, $nameserver );
  return;
}

sub _authority {
  my $packet = shift || return;
    my %hints;
    if (my @ans = $packet->authority) {
      foreach my $rr (@ans) {
            if ( $rr->type eq 'NS') {
          # Found root authority
          my $server = lc $rr->rdatastr;
          $server =~ s/\.$//;
          $hints{$server} = [];
        }
      }
      foreach my $rr ($packet->additional) {
        if (my $server = lc $rr->name){
              push @{ $hints{$server} }, $rr->rdatastr if $rr->type eq 'A' and $hints{$server};
        }
      }
    }
  return \%hints;
}

sub _read_socket {
  my $socket = shift || return;
  $poe_kernel->select_read( $socket );
  my $message;
  unless ( $socket->recv( $message, 512 ) ) {
     warn "$!\n";
     return;
  }
  my ($in,$err);
  {
     local *STDOUT;
     ($in, $err) = Net::DNS::Packet->new( \$message, 1 );
  }
  if ( $err ) {
     warn "$err\n";
     return;
  }
  my $size = length( $in->data );
  unless ( $size ) {
     warn "Bad size\n";
     return;
  }
  return $in;
}

sub _ns_from_cache {
  my $hashref = shift || return;
  my @ns;
  foreach my $ns (keys %{ $hashref }) {
    push @ns, @{ $hashref->{$ns} } if scalar @{ $hashref->{$ns} };
  }
  return @ns;
}

'Recursive lookup, recursive lookup, recursive lookup ....';
__END__

=head1 NAME

POE::Component::Client::DNS::Recursive - A recursive DNS client for POE

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 CONSTRUCTOR

=over

=item C<resolve>

  'event', the event to emit;
  'host', what to look up;
  'type', defaults to 'A' or 'PTR' if 'host' appears to be an IP address;
  'class', defaults to 'IN';
  'port', the port to use for DNS requests. Default is 53;
  'session',

=back

=head1 METHODS

=head1 OUTPUT EVENTS

=head1 AUTHOR

Chris C<BinGOs> Williams <chris@bingosnet.co.uk>

=head1 LICENSE

Copyright E<copy> Chris Williamss.

This module may be used, modified, and distributed under the same terms as Perl itself. Please see the license that came with your Perl distribution for details.

=head1 SEE ALSO

L<POE::Component::Client::DNS>

=cut
