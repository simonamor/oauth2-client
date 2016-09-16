use utf8;
package OAuth2Client::Schema::Result::User;

use strict;
use warnings;

use Moose;
use MooseX::NonMoose;
use MooseX::MarkAsMethods autoclean => 1;
extends 'DBIx::Class::Core';

__PACKAGE__->table("users");

__PACKAGE__->add_columns(
    "id",                   { data_type => "integer", extra => { unsigned => 1 }, is_nullable => 0, },
    "password",             { data_type => "text", is_nullable => 1 },
    "email_address",        { data_type => "text", is_nullable => 1 },
    "first_name",           { data_type => "text", is_nullable => 1 },
    "last_name",            { data_type => "text", is_nullable => 1 },
    "active",               { data_type => "integer", is_nullable => 1 },
    "username",             { data_type => "char", is_nullable => 0, size => 32 },
    "last_password_change", { date_type => "integer", is_nullable => 0, default_value => 0 },
    "last_login_time",      { date_type => "integer", is_nullable => 0, default_value => 0 },
);

__PACKAGE__->set_primary_key("id");

__PACKAGE__->meta->make_immutable;

use Data::Dumper;

sub auto_update {
    my ($self, $authinfo, $c) = @_;
    $c->log->debug( "autoupdate with (1) " . Dumper($authinfo));

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
    $c->log->debug( "autoupdate with (2) " . Dumper($authinfo));

    $self->update($authinfo);
    return $self;
}


1;
