import { beforeEach, expect, test, vi } from 'vitest';
import { getClientInfo, getLocation, hasBlockedIp } from './detect';
import { getIpAddress } from './ip';

const IP = '127.0.0.1';

const isLocalhost = vi.mocked(await import('is-localhost-ip'));

vi.mock('is-localhost-ip', () => ({
  default: vi.fn(),
}));

beforeEach(() => {
  vi.resetAllMocks();

  delete process.env.CLIENT_IP_HEADER;
  delete process.env.IGNORE_IP;
  delete process.env.SKIP_LOCATION_HEADERS;
});

test('getIpAddress: Custom header', () => {
  process.env.CLIENT_IP_HEADER = 'x-custom-ip-header';

  expect(getIpAddress(new Headers({ 'x-custom-ip-header': IP }))).toEqual(IP);
});

test('getIpAddress: Custom header set to x-forwarded-for uses leftmost IP in chain', () => {
  process.env.CLIENT_IP_HEADER = 'x-forwarded-for';

  expect(getIpAddress(new Headers({ 'x-forwarded-for': `${IP}, 10.0.0.1, 10.0.0.2` }))).toEqual(IP);
});

test('getIpAddress: CloudFlare header', () => {
  expect(getIpAddress(new Headers({ 'cf-connecting-ip': IP }))).toEqual(IP);
});

test('getIpAddress: Standard header', () => {
  expect(getIpAddress(new Headers({ 'x-forwarded-for': IP }))).toEqual(IP);
});

test('getIpAddress: No header', () => {
  expect(getIpAddress(new Headers())).toEqual(undefined);
});

test('getLocation: returns null for malformed ip', async () => {
  await expect(
    getLocation(
      'not-an-ip',
      new Headers({
        'cf-ipcountry': 'US',
        'cf-region-code': 'CA',
        'cf-ipcity': 'Los Angeles',
      }),
      false,
    ),
  ).resolves.toEqual(null);
});

test('getLocation: treats localhost check errors as non-local', async () => {
  isLocalhost.default.mockRejectedValue(new Error('DNS Lookup failed.'));

  await expect(
    getLocation(
      '8.8.8.8',
      new Headers({
        'cf-ipcountry': 'US',
        'cf-region-code': 'CA',
        'cf-ipcity': 'Los Angeles',
      }),
      false,
    ),
  ).resolves.toEqual({
    country: 'US',
    region: 'US-CA',
    city: 'Los Angeles',
  });
});

test('hasBlockedIp: returns false for malformed client ip with cidr block', () => {
  process.env.IGNORE_IP = '10.0.0.0/8';

  expect(hasBlockedIp('not-an-ip')).toBe(false);
});

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15';

test('getClientInfo: uses a location sent in the payload (fork patch)', async () => {
  // A public ip with no geo database: a lookup would throw, so this proves it is skipped.
  const request = new Request('https://example.com/api/send', {
    headers: { 'cf-ipcountry': 'FR', 'cf-region-code': 'IDF', 'cf-ipcity': 'Paris' },
  });

  await expect(
    getClientInfo(request, {
      ip: '8.8.8.8',
      userAgent: UA,
      country: 'US',
      region: 'CA',
      city: 'Los Angeles',
    }),
  ).resolves.toMatchObject({ country: 'US', region: 'US-CA', city: 'Los Angeles' });

  await expect(
    getClientInfo(request, { ip: '8.8.8.8', userAgent: UA, country: 'US', region: 'US-CA' }),
  ).resolves.toMatchObject({ country: 'US', region: 'US-CA', city: undefined });

  await expect(
    getClientInfo(request, { ip: '8.8.8.8', userAgent: UA, country: 'DE' }),
  ).resolves.toMatchObject({ country: 'DE', region: undefined, city: undefined });
});

test('getClientInfo: without a payload country, a local ip still yields no location', async () => {
  isLocalhost.default.mockResolvedValue(true);

  const request = new Request('https://example.com/api/send', {
    headers: { 'cf-ipcountry': 'FR', 'cf-region-code': 'IDF', 'cf-ipcity': 'Paris' },
  });

  await expect(
    getClientInfo(request, { ip: IP, userAgent: UA, region: 'CA', city: 'Los Angeles' }),
  ).resolves.toMatchObject({ country: undefined, region: undefined, city: undefined });
});
