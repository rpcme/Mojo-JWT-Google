use strictures;
use Test::More;
use Mojo::JWT::Google;
use File::Basename 'dirname';

isa_ok my $g1 = Mojo::JWT::Google->new, 'Mojo::JWT::Google';

# accessors
is $g1->client_email, undef, 'not init';
is $g1->client_email('mysa@developer.gserviceaccount.com'),
  'mysa@developer.gserviceaccount.com', 'service_account set';
is $g1->client_email, 'mysa@developer.gserviceaccount.com',
  'service_account get';
is_deeply $g1->scopes, [], 'no scopes';
is_deeply $g1->scopes('/a/scope'), ['/a/scope'], 'scopes add one scope';
is_deeply $g1->scopes('/b/scope'), ['/a/scope','/b/scope'],
  'scopes add another';
is_deeply $g1->scopes, ['/a/scope','/b/scope'], 'scopes get all';
is $g1->target, 'https://www.googleapis.com/oauth2/v3/token', 'default target';
is $g1->target('https://www.googleapis.com/oauth2/v4/token'),
  'https://www.googleapis.com/oauth2/v4/token', 'override target';
is $g1->target, 'https://www.googleapis.com/oauth2/v4/token', 'fetch target';
is $g1->expire_at, undef, 'unset by default';
is $g1->expire_at('1429812717'), '1429812717', 'expire_at set';
is $g1->expire_at, '1429812717', 'expire_at get';
is $g1->issue_at, undef, 'unset by default';
is $g1->issue_at('1429812717'), '1429812717', 'issue_at set';
is $g1->issue_at, '1429812717', 'issue_at get';
is_deeply $g1->claims, { iss   => 'mysa@developer.gserviceaccount.com',
                         scope => '/a/scope /b/scope',
                         aud   => 'https://www.googleapis.com/oauth2/v4/token',
                         exp   => '1429812717',
                         iat   => '1429812717',
                       }, 'claims based on accessor settings';
is $g1->user_as, undef, 'impersonate user undef by default';
is $g1->user_as('riche@cpan.org'), 'riche@cpan.org', 'set user';
is $g1->user_as, 'riche@cpan.org', 'get user';
is_deeply $g1->claims, { iss   => 'mysa@developer.gserviceaccount.com',
                         scope => '/a/scope /b/scope',
                         aud   => 'https://www.googleapis.com/oauth2/v4/token',
                         exp   => '1429812717',
                         iat   => '1429812717',
                         sub   => 'riche@cpan.org',
                       }, 'claims based on accessor settings w impersonate';


isa_ok my $g2 = Mojo::JWT::Google->new, 'Mojo::JWT::Google';
# we must set this
is $g2->client_email('mysa@developer.gserviceaccount.com'),
  'mysa@developer.gserviceaccount.com', 'service_account set';
# we must set this
is_deeply $g2->scopes('/a/scope'), ['/a/scope'], 'scopes add one scope';

my $claims = $g2->claims;

# predefine
isa_ok my $g3 = Mojo::JWT::Google->new( scopes => ['/scope/a/', '/scope/b/']),
  'Mojo::JWT::Google';

# predefine w json file
my $tdir = dirname ( __FILE__ );
isa_ok my $g4 = Mojo::JWT::Google->new( from_json => $tdir . '/load1.json' ),
  'Mojo::JWT::Google';
is $g4->secret, <<EOF, 'secret match';
-----BEGIN PRIVATE KEY-----
MIIC
k8KLWw6r/ERRBg==
-----END PRIVATE KEY-----
EOF

is $g4->client_email, '9dvse@developer.gserviceaccount.com',
  'client email matches';

is $g4->from_json, 0, 'requires parameter';
is $g4->from_json('/foo/bar/baz/me'), 0, 'file must exist';
is $g4->from_json( $tdir . '/load3.json' ), 0, 'must have key defined';
is $g4->from_json( $tdir . '/load4.json' ), 0, 'must be for service account';

done_testing;
