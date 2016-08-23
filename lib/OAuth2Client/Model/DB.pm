package OAuth2Client::Model::DB;

use strict;
use base 'Catalyst::Model::DBIC::Schema';

__PACKAGE__->config(
    schema_class => 'OAuth2Client::Schema',

    connect_info => {
        dsn => 'dbi:mysql:oauth2_client',
        user => 'oauth2_client',
        password => 'set-this-in-oauth2client.yml',
        # This is important because otherwise some bad SQL may be generated
        quote_names => 1,
    }
);

=head1 NAME

OAuth2Client::Model::DB - Catalyst DBIC Schema Model

=head1 SYNOPSIS

See L<OAuth2Client>

=head1 DESCRIPTION

L<Catalyst::Model::DBIC::Schema> Model using schema L<OAuth2Client::Schema>

=head1 GENERATED BY

Catalyst::Helper::Model::DBIC::Schema - 0.65

=head1 AUTHOR

A clever guy

=head1 LICENSE

This library is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
