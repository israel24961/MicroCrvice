CREATE table if not exists users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user VARCHAR(63) NOT NULL unique,
    email VARCHAR(63) NOT NULL unique,
    pass VARCHAR(63) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, 
    deleted TIMESTAMP DEFAULT NULL
);
CREATE TABLE if not exists logins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    duration tinyint unsigned default 5,
    token BINARY(16) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    invalidated_at timestamp ,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
