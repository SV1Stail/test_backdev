sudo su - postgres -c "createdb backdev"
grant all privileges on database backdev to user_db;
psql -U user_db -d backdev -h localhost
passw 1234

CREATE TABLE refresh_tokens (
    id SERIAL PRIMARY KEY, 
    user_id UUID NOT NULL,
    token_id UUID NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITHOUT TIME ZONE,
    UNIQUE(user_id)
);

