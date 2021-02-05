/* 
 */
SHOW DATABASES;                -- List the name of all the databases in this server
USE mysql;                     -- Set system database 'mysql' as the current database
SELECT user, host FROM mysql.user;   -- List all users by querying table 'user'
