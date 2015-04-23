package Mojo::JWT::Google;
use parent Mojo::JWT;
use strictures;
use vars qw($VERSION);
use Time::HiRes qw/gettimeofday/;
use Mojo::Util qw(slurp);
use Mojo::JSON qw(decode_json);

BEGIN {
  $Mojo::JWT::Google::VERSION = '0.01';
}
my $grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer";


=head1 NAME

Mojo::JWT::Google - Service Account tokens

=head1 VERSION

0.01

=head1 SYNOPSIS

my $gjwt = Mojo::JWT::Google->new(secret => 's3cr3t',
                                  scopes => [ '/my/scope/a', '/my/scope/b' ],
                                  client_email => 'riche@cpan.org')->encode;

=head1 DESCRIPTION

Like L<Mojo::JWT>, you can instantiate this class by using the same syntax,
except that this class constructs the claims for you.

 my $jwt = Mojo::JWT::Google->new(secret => 's3cr3t')->encode;

And add any attribute defined in this class.  The JWT is fairly useless unless
you define your scopes.

 my $gjwt = Mojo::JWT::Google->new(secret => 's3cr3t',
                                   scopes => [ '/my/scope/a', '/my/scope/b' ],
                                   client_email => 'riche@cpan.org')->encode;

You can also get your information automatically from the .json you received
from Google.  Your secret key is in that file, so it's best to keep it safe
somewhere.  This will ease some busy work in configuring the object -- with
virtually the only things to do is determine the scopes and the user_as if you
need to impersonate.

my $gjwt = Mojo::JWT::Google
  ->new( from_json => '/my/secret.json',
         scopes    => [ '/my/scope/a', '/my/scope/b' ])->encode;


=cut



sub new {
  my ($class, %options) = @_;
  my $self = bless \%options, $class;
  $self->{scopes} = [] if not defined $self->{scopes};
  $self->from_json($self->{from_json}) if defined $self->{from_json};
  return $self;
}

=head1 ATTRIBUTES

L<Mojo::JWT::Google> inherits all attributes from L<Mojo::JWT> and defines the
following new ones.

=head2 claims

Overrides the parent class and constructs a hashref representing Google's
required attribution.

=cut

sub claims {
  my ($self) = @_;

  $self->issue_at( defined $self->issue_at   ? $self->issue_at :
                                               (gettimeofday)[0] );

  $self->expire_at( defined $self->expire_at ? $self->expire_at :
                                               $self->issue_at + 3600 );

  my $result = { iss   => $self->client_email,
                 scope => join( ' ', @{ $self->scopes } ),
                 aud   => $self->target,
                 exp   => $self->expire_at,
                 iat   => $self->issue_at,
               };

  $result->{sub} = $self->user_as if defined $self->user_as;
  return $result;
}

=head2 user_as

Set the Google user to impersonate.  Your Google Business Administrator must
have already set up your Client ID as a trusted app in order to use this
successfully.

=cut

sub user_as {
  my ($self, $value) = @_;
  $self->{user_as} = $value if defined $value;
  return $self->{user_as};
}

=head2 scopes

Get or set the Google scopes.  If impersonating, these scopes must be set up by
your Google Business Administrator.

=cut

sub scopes {
  my ($self, $value) = @_;
  push @{ $self->{scopes} }, $value if defined $value;
  return $self->{scopes};
}

=head2 client_email

Get or set the Client ID email address.

=cut

sub client_email {
  my ($self, $value) = @_;
  $self->{client_email} = $value if defined $value;
  return $self->{client_email};
}

=head2 target

Get or set the target.  At the time of writing, there is only one valid target:
https://www.googleapis.com/oauth2/v3/token.  This is the default value; if you
have no need to customize this, then just fetch the default.

=cut

sub target {
  my ($self, $value) = @_;
  $self->{target} = $value if defined $value;
  $self->{target} = q(https://www.googleapis.com/oauth2/v3/token)
    if not defined $self->{target};
  return $self->{target};
}

=head2 expire_at

Defines when the token expires.  The maximum is 60 minutes from the issue
epoch time.  The default is 60 minutes from the issue epoch time.

=cut

sub expire_at {
  my ($self, $value) = @_;
  $self->{expire_at} = $value if defined $value;
  return $self->{expire_at};
}

=head2 issue_at

Defines the time of issuance in epoch seconds. If not defined, the claims issue
at date defaults to the time when it is being encoded.

=cut

sub issue_at {
  my ($self, $value) = @_;
  $self->{issue_at} = $value if defined $value;
  return $self->{issue_at};
}

=head1 METHODS

Inherits all methods from L<Mojo::JWT> and defines the following new ones.

=head2 from_json

Loads the JSON file from Google with the client ID information in it and sets
the respective attributes.

Returns 0 on failure: file not found or value not defined

 $gjwt->from_json('/my/google/app/project/sa/json/file');

=cut

sub from_json {
  my ($self, $value) = @_;
  return 0 if not defined $value;
  return 0 if not -f $value;
  my $json = decode_json( slurp ( $value ) );
  return 0 if not defined $json->{private_key};
  return 0 if $json->{type} ne 'service_account';
  $self->secret($json->{private_key});
  $self->client_email($json->{client_email});
}

1;

=head1 SEE ALSO

L<Mojo::JWT>

SOURCE REPOSITORY

L<http://github.com/rpcme/Mojo-JWT-Google>

=head1 AUTHOR

Richard Elberger, <riche@cpan.org>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 by Richard Elberger

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.
