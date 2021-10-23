use Test2::V0;

use DBI;

my $dbh;
for (1..100) {
    $dbh = eval {
        DBI->connect('dbi:mysql:dbname=demo;host=127.0.0.1',
            'site',
            '84aaa213dbb7aa3d67d57ba49acc2a71b7c4cd8bf689bfdf4372e4a34dceeca0',
            { RaiseError => 1, AutoCommit => 1}
        );
    };
    last if $dbh;
    select(undef, undef, undef, 0.25);
}
die "Failed to connect $@" unless $dbh;
ok $dbh, 'Connected';

my $bigstring = "this is another long line of text line ...\n" x 1500;
my @values = (
		"foo",
		1, 2, 3, 4,
		"ksmlkmdsalmdlsamdlmsamdskmad lksmsakdma slkmd lsamdkmals da",
		"mdksamkdsmd msakdmskam dsa",
		$bigstring x 3, 6,
);
$dbh->do(<<'SQL', undef, @values);
	INSERT INTO demo.lots
		(Neque_tempore_est_expedita_omn,
		 Enim_rem_consequuntur_ipsum_na,
		 Similique_et_molestias_modi_si,
		 Eligendi_sed_placeat_nihil_vol,
		 Voluptatum_possimus_sint_venia,
		 Incidunt_deleniti_sunt_ea_reru,
		 Labore_distinctio_cum_vero_mol,
		 Aut_suscipit_nihil_voluptatum_,
		 Corporis_et_facere_voluptatem,
		 Minus_sunt_ut_repudiandae,
		 Sed_dolor_est_reprehenderit_a_)
	VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )
SQL

my $res = $dbh->selectall_arrayref('SELECT * FROM demo.lots', { Slice => {} });
use Data::Dumper;
diag Dumper($res);

done_testing;

