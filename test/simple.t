use Test2::V0;

use DBI;

ok my $dbh = DBI->connect('dbi:mysql:dbname=demo;host=localhost;compress=1', 'site', '84aaa213dbb7aa3d67d57ba49acc2a71b7c4cd8bf689bfdf4372e4a34dceeca0', { RaiseError => 1, AutoCommit => 1} );

my $res = $dbh->selectall_arrayref('SELECT * FROM peeps', { Slice => {} });
use Data::Dumper;
diag Dumper($res);

done_testing;