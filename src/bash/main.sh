#!/bin/bash
sleep 3

export PGPASSWORD=1234

echo "PostgreSQL is ready. Running the init.sql script..."
psql -h db -U user_db -d backdev -f /root/bash/init.sql
