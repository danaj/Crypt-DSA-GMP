#!/usr/bin/env perl
use strict;
use warnings;

use Test::More;
use Crypt::DSA::GMP;
use Crypt::DSA::GMP::Util qw( mod_exp );

my @sizes = (qw/512 768 1024/);
push @sizes, 2048 if $ENV{EXTENDED_TESTING};

plan tests => 4 * scalar @sizes;


my $dsa = Crypt::DSA::GMP->new;
foreach my $bits (@sizes) {
  diag "Generating $bits-bit key..." if $bits > 1024;
  my $key = $dsa->keygen( Size => $bits, NonBlockingKeyGeneration => 1 );
  ok($key, "Key generated, $bits bits");
  ok($key->validate, "Key passed simple validation");
  my($L, $N) = $key->sizes;
  is($L, $bits, "P is $bits bits");
  is($N, 160, "Q is 160 bits (FIPS 186-2 standard size)");
  # Note: the two consistency checks from Crypt::DSA are now performed
  # for every generated key before returning, and also before sign & verify.
}
