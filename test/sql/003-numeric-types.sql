USE demo;
CREATE TABLE dbtypes (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    tiny tinyint,
    med MEDIUMINT,
    small smallint,
    basic int,
    big bigint,
    utiny tinyint unsigned,
    umed MEDIUMINT unsigned,
    usmall smallint unsigned,
    ubasic int unsigned,
    ubig bigint unsigned,
    salary decimal(5,2),
    floater float,
    doubled double,
    bits bit(3)
);
