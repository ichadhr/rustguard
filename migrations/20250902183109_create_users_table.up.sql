-- Add up migration script here

CREATE TABLE users (
    id UUID NOT NULL PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    password VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    refresh_token_hash VARCHAR(255),
    refresh_token_expires_at TIMESTAMPTZ,
    refresh_token_family VARCHAR(100)
);

-- Create indexes for better performance
CREATE INDEX users_username_idx ON users (username);
CREATE INDEX users_email_idx ON users (email);
CREATE INDEX users_refresh_token_hash_idx ON users (refresh_token_hash);
CREATE INDEX users_refresh_token_expires_at_idx ON users (refresh_token_expires_at);
