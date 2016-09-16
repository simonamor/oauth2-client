package OAuth2Client::Store::OAuth2DBIC::User;

use base Catalyst::Authentication::Store::DBIx::Class::User;

use Crypt::JWT;
use Crypt::OpenSSL::RSA;

use JSON;
use LWP::UserAgent;
use HTTP::Request;

use strict;
use warnings;

use Data::Dumper;

$Data::Dumper::Maxdepth = 3;

sub load {
    my ($self, $authinfo, $c) = @_;

    $c->log->debug( "Doing stuff.. with " . Dumper($authinfo));

    my $profile = undef;

    # Should have either { id => xxx } or { token => yyy } in $authinfo

    if ($authinfo->{ id }) {
        # This is fine..

    } elsif ($authinfo->{ token }) {
        my $req = HTTP::Request->new( GET => 'https://login.ext2.bocks.com/api/profile');
        $req->header('Authorization' => 'Bearer ' . $authinfo->{ token });
        my $ua = LWP::UserAgent->new();
        my $res = $ua->request( $req );
        if ($res->is_success) {
            my $json = JSON->new();
            $profile = $json->decode($res->content);
            $authinfo = $profile;
            $authinfo->{ id } = delete $authinfo->{ user_id };
            #$authinfo = { id => $profile->{ user_id } };
        } else {
            # No way to fetch anything since token is invalid.
            return undef;
        }
    } else {
        # No way to fetch anything without an id or token
        return undef;
    }

    $c->log->debug( "authinfo is now " . Dumper($authinfo));
    return $self->SUPER::load($authinfo, $c);
}

1;
