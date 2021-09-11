use Test2::V0;

use DBI;

my $dbh;
for (1..100) {
    $dbh = eval {
        DBI->connect('dbi:mysql:dbname=demo;host=127.0.0.1;mysql_compression=1', 'site', '84aaa213dbb7aa3d67d57ba49acc2a71b7c4cd8bf689bfdf4372e4a34dceeca0', { RaiseError => 1, AutoCommit => 1} );
    };
    last if $dbh;
    select(undef, undef, undef, 0.25);
}
die "Failed to connect $@" unless $dbh;
ok $dbh, 'Connceted';

my $res = $dbh->selectall_arrayref('SELECT * FROM peeps', { Slice => {} });
use Data::Dumper;
diag Dumper($res);

done_testing;
