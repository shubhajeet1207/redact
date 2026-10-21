// Bundled synthetic samples (TRD §10.2). Every value is fake and exists only to show the rules.

export interface Sample {
  id: string;
  label: string;
  text: string;
}

export const SAMPLES: readonly Sample[] = [
  {
    id: 'api',
    label: 'API log',
    text: [
      '2026-10-21T09:14:02Z INFO  request id=7f3a method=POST path=/v1/charges user=alex@example.com',
      '2026-10-21T09:14:02Z DEBUG headers Authorization: Bearer fake-bearer-token-0001 Cookie: session=fake-session-42; theme=dark',
      '2026-10-21T09:14:03Z DEBUG upstream url=https://svc:fake-pass-9@api.internal.example/v2/charge',
      '2026-10-21T09:14:03Z WARN  retrying with token=ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000 from 10.0.4.17',
      '2026-10-21T09:14:04Z INFO  done status=201 duration_ms=212',
    ].join('\n'),
  },
  {
    id: 'config',
    label: 'Config excerpt',
    text: [
      '# app.env — synthetic example',
      'APP_ENV=production',
      'DB_PASSWORD=fake-db-password',
      'export AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKE0000',
      'REDIS_URL=redis://:fake-redis-pass@cache.internal:6379/0',
      'LOG_DIR=/home/alex/app/logs',
      '{"client_id": "web-app", "client_secret": "fake-client-secret", "max_tokens": 4096}',
      '-----BEGIN PRIVATE KEY-----',
      'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCFAKEFAKEFAKEFAKE',
      'FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE',
      '-----END PRIVATE KEY-----',
    ].join('\n'),
  },
  {
    id: 'trace',
    label: 'Stack trace',
    text: [
      'Traceback (most recent call last):',
      '  File "/Users/alex/projects/shop/app.py", line 88, in checkout',
      '    charge = client.charge(api_key="fake-api-key-123", amount=4200)',
      '  File "C:\\Users\\alex\\venv\\lib\\site-packages\\pay\\client.py", line 41, in charge',
      '    raise AuthError(f"rejected token sk_test_FAKEFAKEFAKEFAKE1234 for {email}")',
      'pay.errors.AuthError: rejected token for alex@example.com',
    ].join('\n'),
  },
];
