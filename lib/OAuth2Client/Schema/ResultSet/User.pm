package OAuth2Client::Schema::ResultSet::User;

use parent 'DBIx::Class::ResultSet';

use strict;
use warnings;

use Data::Dumper;
use JSON;
use HTTP::Request;
use LWP::UserAgent;

sub auto_create {
    my ($self, $authinfo, $c) = @_;
    $c->log->debug( "autocreate with (1) " . Dumper($authinfo));

    if (exists $authinfo->{ token }) {
        my $req = HTTP::Request->new( GET => 'https://login.ext2.bocks.com/api/profile');
        $req->header('Authorization' => 'Bearer ' . $authinfo->{ token });
        my $ua = LWP::UserAgent->new();
        my $res = $ua->request( $req );
        if ($res->is_success) {
            my $json = JSON->new();
            my $profile = $json->decode($res->content);
            $authinfo = $profile;
            $authinfo->{ id } = delete $authinfo->{ user_id };
            $authinfo->{ active } = 1;
        }
    }
    $c->log->debug( "autocreate with (2) " . Dumper($authinfo));
    return $self->find_or_create($authinfo, { key => "primary" });
}

1;
