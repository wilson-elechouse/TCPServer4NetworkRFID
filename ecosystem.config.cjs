module.exports = {
  apps: [
    {
      name: 'elechouse-rfid-tcp-broker',
      script: './server.js',
      cwd: '/opt/elechouse-rfid-tcp-broker',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      max_memory_restart: '256M',
      env: {
        NODE_ENV: 'production',
        HTTP_HOST: '127.0.0.1',
        HTTP_PORT: '19090',
        TCP_HOST: '0.0.0.0',
        TCP_PORT: '9000',
        PUBLIC_TCP_HOST: 'www.elechouse.com',
        PUBLIC_BASE_PATH: '/rfid-tcp-broker',
        // Optional WordPress login gate. Default is off for this repository.
        // Set to '1' and install wordpress/elechouse-rfid-broker-auth.php as an MU plugin to enable it.
        REQUIRE_WEB_AUTH: '0',
        WORDPRESS_AUTH_CHECK_URL: 'http://127.0.0.1/wp-json/elechouse-rfid/v1/auth-check',
        WORDPRESS_AUTH_HOST: 'www.elechouse.com',
        SESSION_TTL_MS: String(30 * 60 * 1000),
        HELLO_TIMEOUT_MS: String(10 * 1000),
        SESSION_CODE_LENGTH: '8',
        MAX_SESSIONS: '200',
        MAX_WEB_CLIENTS_PER_SESSION: '8',
        MAX_TCP_CONNECTIONS_PER_IP: '5',
        MAX_TCP_AUTH_FAILURES_PER_IP: '300',
        TCP_AUTH_FAILURE_WINDOW_MS: String(10 * 60 * 1000),
        TCP_AUTH_BLOCK_MS: String(10 * 60 * 1000)
      }
    }
  ]
};
