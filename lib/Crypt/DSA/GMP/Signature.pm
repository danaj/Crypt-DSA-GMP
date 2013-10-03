package Crypt::DSA::GMP::Signature;
use strict;
use warnings;

BEGIN {
  $Crypt::DSA::GMP::Signature::AUTHORITY = 'cpan:DANAJ';
  $Crypt::DSA::GMP::Signature::VERSION = '0.01';
}

use Carp qw( croak );

sub new {
    my $class = shift;
    my %param = @_;
    my $sig = bless { }, $class;
    if ($param{Content}) {
        return $sig->deserialize(%param);
    }
    $sig;
}

BEGIN {
    no strict 'refs';
    for my $meth (qw( r s )) {
        # Values are stored as Math::BigInt objects
        *$meth = sub {
            my($key, $value) = @_;
            if (defined $value) {
              my $str;
              if (ref($value) eq 'Math::BigInt')  { $key->{$meth} = $value; }
              elsif (ref($value) eq 'Math::Pari') { $str = Math::Pari::pari2pv($value); }
              elsif (ref $value)                  { $str = "$value"; }
              elsif ($value =~ /^0x/)             { $key->{$meth} = Math::BigInt->new($value); }
              else                                { $str = $value; }
              $key->{$meth} = Math::BigInt->new("$str")
                  if defined $str && $str =~ /^\d+$/;
            } elsif (@_ > 1 && !defined $value) {
              delete $key->{$meth};
            }
            $key->{$meth};
        };
    }
}

sub asn {
    require Convert::ASN1;
    my $asn = Convert::ASN1->new;
    $asn->prepare('SEQUENCE { r INTEGER, s INTEGER }') or croak $asn->{error};
    $asn;
}

sub deserialize {
    my $sig = shift;
    my %param = @_;
    my $asn = __PACKAGE__->asn;
    my $ref;
    require MIME::Base64;
    ## Turn off warnings, because we're attempting to base64-decode content
    ## that may not be base64-encoded.
    local $^W = 0;
    for ($param{Content}, MIME::Base64::decode_base64($param{Content})) {
        my $out = $asn->decode($_);
        $ref = $out, last if $out;
    }
    croak "Invalid Content" unless $ref;
    $sig->s($ref->{s});
    $sig->r($ref->{r});
    $sig;
}

sub serialize {
    my $sig = shift;
    my %param = @_;
    my $asn = __PACKAGE__->asn;
    my $buf = $asn->encode({ s => $sig->s, r => $sig->r })
        or croak $asn->{error};
    $buf;
}

1;
__END__

=head1 NAME

Crypt::DSA::Signature - DSA signature object

=head1 SYNOPSIS

    use Crypt::DSA::Signature;
    my $sig = Crypt::DSA::Signature->new;

    $sig->r($r);
    $sig->s($s);

=head1 DESCRIPTION

I<Crypt::DSA::Signature> represents a DSA signature. It has 2 methods,
I<r> and I<s>, which are the big number representations of the 2 pieces of
the DSA signature.

=head1 USAGE

=head2 Crypt::DSA::Signature->new( %options )

Creates a new signature object, and optionally initializes it with the
information in I<%options>, which can contain:

=over 4

=item * Content

An ASN.1-encoded string representing the DSA signature. In ASN.1 notation,
this looks like:

    SEQUENCE {
        r INTEGER,
        s INTEGER
    }

If I<Content> is provided, I<new> will automatically call the I<deserialize>
method to parse the content, and set the I<r> and I<s> methods on the
resulting I<Crypt::DSA::Signature> object.

=back

=head2 $sig->serialize

Serializes the signature object I<$sig> into the format described above:
an ASN.1-encoded representation of the signature, using the ASN.1 syntax
above.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::DSA manpage for author, copyright,
and license information.

=cut
