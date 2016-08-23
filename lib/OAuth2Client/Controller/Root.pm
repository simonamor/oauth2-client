package OAuth2Client::Controller::Root;
use Moose;
use namespace::autoclean;

use URI;
use Digest::SHA;
use Time::HiRes;

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

    use Data::Dumper;
    if ($c->request->param('error')) {
        $c->stash( template => "error.html" );
        $c->stash( extra => $c->request->params );
        $c->detach();
    }

    my $sha1 = Digest::SHA->new(512)->add(
        $$, "Auth for login", Time::HiRes::time(), rand()*10000
    )->hexdigest;
    $sha1 = substr($sha1, 4, 16);

    unless ($c->request->param('state')) {
        $c->session( oauth_state => $sha1 );
    }

    my %scope = ();
    if ($c->config->{'Plugin::Authentication'}{default}{credential}{scope}) {
        $scope{ scope } = $c->config->{'Plugin::Authentication'}{default}{credential}{scope};
    }

    if ($c->authenticate({
            state => $sha1,
            %scope,
        })) {
        $c->log->debug("Authenticated!");

        # At this point, there would be a call using the oauth token to fetch
        # user data such as email address
        $c->response->redirect($c->uri_for("/status"));
        $c->detach();
    }
    $c->log->debug("Not authenticated");
}

sub status :Path('/status') :Args(0) {
    my ($self, $c) = @_;

    $c->stash( template => "status.html" );
}

sub logout :Path('/logout') :Args(0) {
    my ($self, $c) = @_;

    $c->logout();
    $c->response->redirect($c->uri_for("/"));
}

sub protected :Chained('/') :Args(0) Does('OAuth2::ProtectedResource') {
    my ($self, $c) = @_;

    $c->log->debug("Here at line " . __LINE__);

    $c->stash( template => "protected.html" );
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
