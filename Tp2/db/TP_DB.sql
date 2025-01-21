CREATE DATABASE TP_DB;

USE TP_DB;

CREATE TABLE users (
    id int,
    name varchar(255)
);

INSERT INTO users (id, name)
VALUES
("1", "Gros_Bot"),
("2", "Second_Bot"),
("3", "Trop_de_bot"),
("4", "Mommo");

CREATE USER 'meow'@'%' IDENTIFIED BY 'meow';
GRANT ALL PRIVILEGES ON *.* TO 'meow'@'%';