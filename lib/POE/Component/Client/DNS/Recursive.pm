package POE::Component::Client::DNS::Recursive;

use strict;
use warnings;

use vars qw($VERSION);

$VERSION = '0.02';

sub resolve {
  my $package = shift;
  my %opts = @_;
  $opts{lc $_} = delete $opts{$_} for keys %opts;
  my $options = delete $opts{options};
  my $self = bless \%opts, $package;
  
  return $self;
}

'Recursive lookup, recursive lookup, recursive lookup ....';
__END__
