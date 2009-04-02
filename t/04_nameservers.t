use strict;
use warnings;
use Test::More; # tests => 5;
use Net::DNS;
use POE qw(Component::Client::DNS::Recursive);

my @ns;

{ 
  my $res = Net::DNS::Resolver->new();
  @ns = $res->nameservers();
}

plan skip_all => 'Could not determine a local nameserver to query' unless scalar @ns;

plan tests => 5;

POE::Session->create(
  package_states => [
	'main', [qw(_start _stop _child _response)],
  ],
);

$poe_kernel->run();
exit 0;

sub _start {
  POE::Component::Client::DNS::Recursive->resolve(
	event => '_response',
	host => 'www.google.com',
	nameservers => \@ns,
  );
  return;
}

sub _stop {
  pass('Reference has gone');
  return;
}

sub _child {
  pass('Child ' . $_[ARG0]);
  return;
}

sub _response {
  my $packet = $_[ARG0]->{response};
  return unless $packet;
  isa_ok( $packet, 'Net::DNS::Packet' );
  ok( scalar $packet->answer, 'We got answers' );
  return;
}