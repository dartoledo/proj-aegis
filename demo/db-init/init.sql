CREATE TABLE items (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    status VARCHAR(50)
);

INSERT INTO items (name, status) VALUES 
('Auth', 'Online');
