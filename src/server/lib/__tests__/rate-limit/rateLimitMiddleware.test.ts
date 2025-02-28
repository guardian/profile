import Redis from 'ioredis-mock';
import request from 'supertest';
import { NextFunction, Request } from 'express';
import { RateLimiterConfiguration } from '@/server/lib/rate-limit';
import { getServerInstance } from '../sharedConfig';
import {
	RequestWithCsrf,
	ResponseWithRequestState,
} from '@/server/models/Express';

// Override the default 5s max timeout for these tests because Supertest takes some time to run.
jest.setTimeout(20000);

describe('rate limiter middleware', () => {
	const loggerInfoMock = jest.fn();

	beforeEach(() => {
		jest.clearAllMocks();
		jest.resetModules();
		jest.useFakeTimers();

		jest.mock('@/server/lib/getAssets', () => ({
			getAssets: () => ({
				main: { js: 'mocked' },
				vendors: { js: 'mocked' },
				runtime: { js: 'mocked' },
			}),
		}));

		jest.mock('@aws-sdk/credential-providers');
		jest.mock('@smithy/node-http-handler');
		jest.mock('@aws-sdk/client-sesv2');
		jest.mock('@aws-sdk/client-cloudwatch');
		jest.mock('@/server/lib/idapi/user');
		jest.mock('@/server/lib/idapi/decryptToken');
		jest.mock('@/server/lib/idapi/IDAPICookies');
		jest.mock('@/server/lib/trackMetric');

		jest.mock('@/server/lib/serverSideLogger', () => ({
			logger: {
				info: loggerInfoMock,
				warn: jest.fn(),
			},
		}));
		jest.mock('@/server/controllers/sendChangePasswordEmail', () => ({
			sendEmailInOkta: (req: Request, res: ResponseWithRequestState) =>
				res.redirect(303, '/reset-password/email-sent'),
		}));

		jest.mock('@/server/lib/middleware/csrf', () => ({
			csrfMiddleware: (
				req: RequestWithCsrf,
				res: ResponseWithRequestState,
				next: NextFunction,
			) => {
				// eslint-disable-next-line functional/immutable-data
				req.csrfToken = () => 'mocked-csrf-token';
				next();
			},
		}));

		jest.mock('@/server/lib/recaptcha', () =>
			jest.fn((req, res, next) => {
				// eslint-disable-next-line functional/immutable-data
				req.recaptcha = { error: false };
				next();
			}),
		);

		jest.mock('@/server/lib/redis/redisClient', () => new Redis());

		jest.mock('@okta/jwt-verifier');
	});

	afterEach((done) => {
		// in-memory redis store is persisted after each run
		// make sure to clear the store after each test
		void new Redis().flushall().then(() => done());
	});

	afterAll(() => {
		// Reset fake timers.
		jest.runOnlyPendingTimers();
		jest.useRealTimers();
	});

	it('should rate limit all clients when the global bucket is empty', async () => {
		const rateLimiterConfig: RateLimiterConfiguration = {
			enabled: true,
			settings: {
				logOnly: false,
				trackBucketCapacity: false,
			},
			defaultBuckets: {
				globalBucket: { capacity: 2, addTokenMs: 500 },
			},
		};

		const server = await getServerInstance(rateLimiterConfig);
		// Consume both global tokens, expect third request to be limited.
		await request(server).get('/register').expect(200);
		await request(server).get('/register').expect(200);
		await request(server).get('/register').expect(429);

		jest.advanceTimersByTime(500);

		// After waiting, user can make a request again.
		await request(server).get('/register').expect(200);
	});

	it('should rate limit when the ip rate limit bucket is empty', async () => {
		const rateLimiterConfig: RateLimiterConfiguration = {
			enabled: true,
			settings: {
				logOnly: false,
				trackBucketCapacity: false,
			},
			defaultBuckets: {
				globalBucket: { capacity: 10, addTokenMs: 500 },
				ipBucket: { capacity: 2, addTokenMs: 500 },
			},
		};

		// Start the application server.
		const server = await getServerInstance(rateLimiterConfig);

		// After two requests, 192.168.2.1 should hit the rate limit.
		await request(server)
			.get('/register')
			.set('X-Forwarded-For', '192.168.2.1')
			.expect(200);
		await request(server)
			.get('/register')
			.set('X-Forwarded-For', '192.168.2.1')
			.expect(200);
		await request(server)
			.get('/register')
			.set('X-Forwarded-For', '192.168.2.1')
			.expect(429);

		expect(loggerInfoMock).toHaveBeenLastCalledWith(
			`RateLimit-Gateway ipBucket email=undefined ip=192.168.2.1 accessToken= identity-gateway GET /register`,
		);

		// 192.168.2.7 should be allowed to make a request.
		await request(server)
			.get('/register')
			.set('X-Forwarded-For', '192.168.2.7')
			.expect(200);

		jest.advanceTimersByTime(500);

		// After 500ms 192.168.2.1 can make a request again.
		await request(server)
			.get('/register')
			.set('X-Forwarded-For', '192.168.2.1')
			.expect(200);
	});

	it('should rate limit when the access token bucket is empty', async () => {
		const rateLimiterConfig: RateLimiterConfiguration = {
			enabled: true,
			settings: {
				logOnly: false,
				trackBucketCapacity: false,
			},
			defaultBuckets: {
				globalBucket: { capacity: 10, addTokenMs: 500 },
				accessTokenBucket: { capacity: 2, addTokenMs: 500 },
			},
		};

		// Start the application server.
		const server = await getServerInstance(rateLimiterConfig);

		// After two requests, GU_ACCESS_TOKEN=test should hit the rate limit.
		await request(server)
			.get('/register')
			.set('Cookie', 'GU_ACCESS_TOKEN=verylongaccesstoken')
			.expect(200);
		await request(server)
			.get('/register')
			.set('Cookie', 'GU_ACCESS_TOKEN=verylongaccesstoken')
			.expect(200);
		await request(server)
			.get('/register')
			.set('Cookie', 'GU_ACCESS_TOKEN=verylongaccesstoken')
			.expect(429);

		// Expect the access token to be truncated so we don't exceed the maximum message size for message.keywords in Kibana.
		expect(loggerInfoMock).toHaveBeenLastCalledWith(
			`RateLimit-Gateway accessTokenBucket email=undefined ip=::ffff:127.0.0.1 accessToken=verylo identity-gateway GET /register`,
		);

		// GU_ACCESS_TOKEN=other should be allowed to make a request
		await request(server)
			.get('/register')
			.set('Cookie', 'GU_ACCESS_TOKEN=other')
			.expect(200);

		jest.advanceTimersByTime(500);

		// After waiting, GU_ACCESS_TOKEN=test can make a request again.
		await request(server)
			.get('/register')
			.set('Cookie', 'GU_ACCESS_TOKEN=verylongaccesstoken')
			.expect(200);
	});

	it('should not apply the rate limiter when logOnly is set to true', async () => {
		const rateLimiterConfig: RateLimiterConfiguration = {
			enabled: true,
			settings: {
				logOnly: true,
				trackBucketCapacity: false,
			},
			defaultBuckets: {
				enabled: true,
				globalBucket: { capacity: 1, addTokenMs: 500 },
			},
		};

		// Start the application server.
		const server = await getServerInstance(rateLimiterConfig);

		// Confirm that we are not rate limited when logOnly is set to true.
		await request(server).get('/signin').expect(200);
		await request(server).get('/signin').expect(200);
	});

	it('should not apply the rate limiter when logOnly is set to true for a single route', async () => {
		const rateLimiterConfig: RateLimiterConfiguration = {
			enabled: true,
			settings: {
				logOnly: false,
				trackBucketCapacity: false,
			},
			defaultBuckets: {
				enabled: true,
				globalBucket: { capacity: 1, addTokenMs: 500 },
			},
			routeBuckets: {
				'/signin': {
					settings: {
						logOnly: true,
					},
					globalBucket: { capacity: 1, addTokenMs: 500 },
				},
			},
		};

		// Start the application server.
		const server = await getServerInstance(rateLimiterConfig);

		// Confirm that we are not rate limited when logOnly is set to true.
		// We have only applied the rate limiter to the /signin route, so we should not be rate limited.
		await request(server).get('/signin').expect(200);
		await request(server).get('/signin').expect(200);

		// Confirm that other routes are still rate limited.
		await request(server).get('/register').expect(200);
		await request(server).get('/register').expect(429);
	});

	it('should allow you to disable rate limiting for selected routes ', async () => {
		const rateLimiterConfig: RateLimiterConfiguration = {
			enabled: true,
			settings: {
				logOnly: false,
				trackBucketCapacity: false,
			},
			defaultBuckets: {
				enabled: true,
				globalBucket: { capacity: 1, addTokenMs: 500 },
			},
			routeBuckets: {
				'/signin': {
					enabled: false,
					globalBucket: { capacity: 1, addTokenMs: 50 },
				},
				'/register': {
					enabled: true,
					globalBucket: { capacity: 1, addTokenMs: 50 },
				},
			},
		};

		// Start the application server.
		const server = await getServerInstance(rateLimiterConfig);

		// Confirm that route: /signin is never rate limited.
		await request(server).get('/signin').expect(200);
		await request(server).get('/signin').expect(200);

		// Confirm that route: /reset-password covered by the defaults is rate limited
		await request(server).get('/reset-password').expect(200);
		await request(server).get('/reset-password').expect(429);

		expect(loggerInfoMock).toHaveBeenLastCalledWith(
			`RateLimit-Gateway globalBucket email=undefined ip=::ffff:127.0.0.1 accessToken= identity-gateway GET /reset-password`,
		);

		// Confirm that enabled overridden route: /register is rate limited.
		await request(server).get('/register').expect(200);
		await request(server).get('/register').expect(429);
	});

	it('should not rate limit disabled routes and only rate limit enabled routes', async () => {
		const rateLimiterConfig: RateLimiterConfiguration = {
			enabled: true,
			settings: {
				logOnly: false,
				trackBucketCapacity: false,
			},
			defaultBuckets: {
				enabled: false,
				globalBucket: { capacity: 1, addTokenMs: 500 },
			},
			routeBuckets: {
				'/reset-password': {
					enabled: true,
					globalBucket: { capacity: 500, addTokenMs: 50 },
					emailBucket: { capacity: 1, addTokenMs: 500 },
				},
				'/signin': {
					enabled: true,
					globalBucket: { capacity: 1, addTokenMs: 50 },
				},
			},
		};

		// Start the application server.
		const server = await getServerInstance(rateLimiterConfig);

		// Confirm that /signin and /reset-password are rate limited.

		// Consume the only token available for this email
		await request(server)
			.post('/reset-password?returnUrl=https%3A%2F%2Fwww.theguardian.com%2Fuk')
			.type('application/x-www-form-urlencoded')
			.send({
				email: 'test@test.com',
			})
			.expect(303);

		// No more tokens left for this email, check that rate limiter kicks in
		await request(server)
			.post('/reset-password')
			.type('application/x-www-form-urlencoded')
			.send({
				email: 'test@test.com',
			})
			.expect(429);

		expect(loggerInfoMock).toHaveBeenLastCalledWith(
			`RateLimit-Gateway emailBucket email=test@test.com ip=::ffff:127.0.0.1 accessToken= identity-gateway POST /reset-password`,
		);

		await request(server).get('/signin').expect(200);
		await request(server).get('/signin').expect(429);

		// Confirm that /register (disabled by the default config) is never rate limited.
		await request(server).get('/register').expect(200);
		await request(server).get('/register').expect(200);
	});

	it('should rate limit /reset-password form when the email bucket is empty', async () => {
		const rateLimiterConfig: RateLimiterConfiguration = {
			enabled: true,
			settings: {
				logOnly: false,
				trackBucketCapacity: false,
			},
			defaultBuckets: {
				globalBucket: { capacity: 500, addTokenMs: 500 },
			},
			routeBuckets: {
				'/reset-password': {
					globalBucket: { capacity: 500, addTokenMs: 50 },
					emailBucket: { capacity: 1, addTokenMs: 500 },
				},
			},
		};

		// Start the application server.
		const server = await getServerInstance(rateLimiterConfig);

		// Consume the only token available for this email
		await request(server)
			.post('/reset-password?returnUrl=https%3A%2F%2Fwww.theguardian.com%2Fuk')
			.type('application/x-www-form-urlencoded')
			.send({
				email: 'test@test.com',
			})
			.expect(303);

		// No more tokens left for this email, check that rate limiter kicks in
		await request(server)
			.post('/reset-password')
			.type('application/x-www-form-urlencoded')
			.send({
				email: 'test@test.com',
			})
			.expect(429);

		// Make sure that the email can't be let through with an email alias
		await request(server)
			.post('/reset-password')
			.type('application/x-www-form-urlencoded')
			.send({
				email: 'test+maliciousalias@test.com',
			})
			.expect(429);

		// Make sure that other emails are still allowed through the rate limiter
		await request(server)
			.post('/reset-password?returnUrl=https%3A%2F%2Fwww.theguardian.com%2Fuk')
			.type('application/x-www-form-urlencoded')
			.send({
				email: 'newTest@test.com',
			})
			.expect(303);

		jest.advanceTimersByTime(500);

		// Check that a new request goes through successfully
		await request(server)
			.post('/reset-password')
			.type('application/x-www-form-urlencoded')
			.send({
				email: 'test@test.com',
			})
			.expect(303);
	});
});
