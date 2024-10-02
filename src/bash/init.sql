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
