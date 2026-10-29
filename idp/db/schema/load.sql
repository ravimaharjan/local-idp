-- Load order of the identity provider's schema. Run by db/init/01-load-schema.sh on a new database.
\ir 00-schema.sql
\ir 10-accounts.sql
\ir 20-apps.sql
\ir 30-tokens.sql
