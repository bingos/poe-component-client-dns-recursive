use strict;
use warnings;
use Test::More;

use POE qw(Component::Client::DNS::Recursive);

POE::Session->create(
  package_states => [
	'main', [qw(_start _response)],
  ],
);

$poe_kernel->run();
exit 0;

sub _start {
  POE::Component::Client::DNS::Recursive->resolve(
	event => '_response',
	host => 'www.google.com',
  );
  return;
}

sub _response {
}
