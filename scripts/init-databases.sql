-- Create databases for different services
CREATE DATABASE athletes_db;
CREATE DATABASE competitions_db;

-- Create test databases
CREATE DATABASE test_auth_db;
CREATE DATABASE test_athletes_db;
CREATE DATABASE test_competitions_db;

-- Grant permissions to the user
GRANT ALL PRIVILEGES ON DATABASE auth_db TO shooteristauser;
GRANT ALL PRIVILEGES ON DATABASE athletes_db TO shooteristauser;
GRANT ALL PRIVILEGES ON DATABASE competitions_db TO shooteristauser;
GRANT ALL PRIVILEGES ON DATABASE test_auth_db TO shooteristauser;
GRANT ALL PRIVILEGES ON DATABASE test_athletes_db TO shooteristauser;
GRANT ALL PRIVILEGES ON DATABASE test_competitions_db TO shooteristauser;
