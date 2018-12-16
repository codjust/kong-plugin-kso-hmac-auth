return {
{
    name = "2018-12009-183100_init_ksohmacauth",
    up = [[
        CREATE TABLE IF NOT EXISTS kso_hmacauth_credentials(
        id uuid,
        consumer_id uuid REFERENCES consumers (id) ON DELETE CASCADE,
        accesskey text UNIQUE,
        secretkey text,
        created_at timestamp without time zone default (CURRENT_TIMESTAMP(0) at time zone 'utc'),
        PRIMARY KEY (id)
      );

      DO $$
      BEGIN
        IF (SELECT to_regclass('kso_hmacauth_credentials_accesskey')) IS NULL THEN
          CREATE INDEX kso_hmacauth_credentials_accesskey ON kso_hmacauth_credentials(accesskey);
        END IF;
        IF (SELECT to_regclass('kso_hmacauth_credentials_consumer_id')) IS NULL THEN
          CREATE INDEX kso_hmacauth_credentials_consumer_id ON kso_hmacauth_credentials(consumer_id);
        END IF;
      END$$;

    ]],
    down = [[
      DROP TABLE kso_hmacauth_credentials;
    ]]

}


}