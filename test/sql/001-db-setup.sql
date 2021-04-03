CREATE DATABASE demo CHARACTER SET utf8mb4;
CREATE USER 'site'@'localhost' IDENTIFIED BY '84aaa213dbb7aa3d67d57ba49acc2a71b7c4cd8bf689bfdf4372e4a34dceeca0';
GRANT SELECT, UPDATE, DELETE, INSERT ON demo.* TO 'site'@'localhost';
