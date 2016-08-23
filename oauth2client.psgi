use strict;
use warnings;

use OAuth2Client;

my $app = OAuth2Client->apply_default_middlewares(OAuth2Client->psgi_app);
$app;

