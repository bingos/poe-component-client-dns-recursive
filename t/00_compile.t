use strict;
use warnings;
use Test::More tests => 1;
BEGIN { use_ok('POE::Component::Client::DNS::Recursive') };
diag( "Testing POE::Component::Client::DNS::Recursive $POE::Component::Client::DNS::Recursive::VERSION, POE $POE::VERSION, Perl $], $^X" );
