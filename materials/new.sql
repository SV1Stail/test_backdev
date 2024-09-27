sudo su - postgres -c "createdb backdev"
grant all privileges on database backdev to user_db;
psql -U user_db -d backdev -h localhost
passw 1234
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

INSERT INTO users (id, username, password) VALUES
('123e4567-e89b-12d3-a456-426614174000', 'user1', 'password1'),
('123e4567-e89b-12d3-a456-426614174001', 'user2', 'password2'),
('123e4567-e89b-12d3-a456-426614174002', 'user3', 'password3'),
ON CONFLICT (id) DO NOTHING;
