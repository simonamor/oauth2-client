package OAuth2Client::Controller::Root;
use Moose;
use namespace::autoclean;

use URI;
use Digest::SHA;
use Time::HiRes;

use Data::Dumper;

BEGIN { extends 'Catalyst::Controller' }

#
# Sets the actions in this controller to be registered with no prefix
# so they function identically to actions created in MyApp.pm
#
__PACKAGE__->config(namespace => '');

=encoding utf-8

=head1 NAME

OAuth2Client::Controller::Root - Root Controller for OAuth2Client

=head1 DESCRIPTION

[enter your description here]

=head1 METHODS

=head2 index

The root page (/)

=cut

sub index :Path :Args(0) {
    my ( $self, $c ) = @_;

    $c->stash( template => "index.html" );
}

=head2 default

Standard 404 error page

=cut

sub default :Path {
    my ( $self, $c ) = @_;
    $c->response->status(404);
    $c->stash( template => "404.html" );
}

sub login :Path('/login') :Args(0) {
    my ($self, $c) = @_;

    if (exists $c->request->params->{ error }) {
        $c->stash( template => "error.html" );
        $c->stash( extra => $c->request->params );
        $c->detach();
    }

    my $sha1 = undef;
    if (exists $c->request->params->{ state }) {
        $sha1 = $c->request->params->{ state };

        if ($sha1 ne $c->session->{ oauth_state }) {
            $c->log->debug("state doesn't match $sha1 vs " . $c->session->{ oauth_state });
        }

    } else {
        $sha1 = Digest::SHA->new(512)->add(
            $$, "Auth for login", Time::HiRes::time(), rand()*10000
        )->hexdigest;
        $sha1 = substr($sha1, 4, 16);

        $c->session( oauth_state => $sha1 );
    }

    my %scope = ();
    if ($c->config->{'Plugin::Authentication'}{default}{credential}{scope}) {
        $scope{ scope } = $c->config->{'Plugin::Authentication'}{default}{credential}{scope};
    }

    $c->log->debug("authenticate this: " . Dumper({ state => $sha1, %scope }));

    if ($c->authenticate({
            state => $sha1,
            %scope,
        })) {
        $c->log->debug("Authenticated!");

        # Fetch information from the Auth Provider to get a unique id
        # that we can use to link a local account to the account that
        # was used at the Provider.

        # FIXME: Get unique id

        # At this point, there would be a call using the oauth token to fetch
        # user data such as email address
        $c->response->redirect($c->uri_for("/status"));
        #$c->detach('/status');
    } elsif (exists $c->req->params->{ code }) {
        # If the code parameter isn't present, we've not yet redirected to the
        # login server for authentication so a redirect is likely already present.
        $c->log->debug("Not authenticated");
        # Here we would need to redirect or something..

        $c->response->redirect($c->uri_for("/login", { error_description => "Login failed", error => "access_denied", %{$c->req->params} }));
    }
}

sub status :Path('/status') :Args(0) {
    my ($self, $c) = @_;

    # No OAuth2 attribute on the user (or logged in user)? Login first.
    unless ($c->user_exists && $c->user->oauth2) {
        $c->response->redirect($c->uri_for("/login"));
        $c->detach();
    }

    # Fetch a 'protected' resource from the login server. Typically this
    # would be something like user data, profile info, etc.
    my $req = HTTP::Request->new( GET => 'https://login.ext2.bocks.com/api/profile');
    my $res = $c->user->oauth2->request( $req );

    if ($res->is_success) {
        $c->stash( response => $res->content );
    } else {
        # If the token no longer works and we get a 401, log them out locally
        # as well so they get asked to re-authenticate.
        if ($res->code == 401) {
            $c->logout();
            $c->detach('/status');
        }
        $c->stash( error => $res->content );
    }
    $c->stash( template => "status.html" );
}

sub logout :Path('/logout') :Args(0) {
    my ($self, $c) = @_;

    if ($c->user_exists && $c->user->oauth2) {
        my $res = $c->user->oauth2->request(
            HTTP::Request->new( GET => 'https://login.ext2.bocks.com/api/revoke' )
        );
    }
    # Not too concerned with the response, the token will die
    # within the normal timeout anyway if there's an error.
    $c->logout();
    $c->response->redirect($c->uri_for("/"));
}

sub end : ActionClass('RenderView') { }

=head1 AUTHOR

Catalyst developer

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;
