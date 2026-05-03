import request from 'supertest';
import app from '../src/app';

describe('PAMSignal Webhook Receiver', () => {
  const SECRET = 'test-secret';

  beforeAll(() => {
    // Set a secret for testing authentication
    process.env.WEBHOOK_SECRET = SECRET;
    // Suppress console.log and console.warn during tests
    jest.spyOn(console, 'log').mockImplementation(() => { });
    jest.spyOn(console, 'warn').mockImplementation(() => { });
  });

  afterAll(() => {
    jest.restoreAllMocks();
  });

  const validPayload = {
    event: { action: 'brute_force_detected' },
    source: { ip: '203.0.113.50' },
    pamsignal: { attempts: 12, window_sec: 300 }
  };

  describe('Authentication', () => {
    it('should reject requests without a token', async () => {
      const response = await request(app)
        .post('/webhook/pamsignal')
        .send(validPayload);

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty('error', 'Unauthorized: Invalid or missing token');
    });

    it('should reject requests with an invalid Bearer token', async () => {
      const response = await request(app)
        .post('/webhook/pamsignal')
        .set('Authorization', 'Bearer wrong-token')
        .send(validPayload);

      expect(response.status).toBe(401);
    });

    it('should accept requests with a valid Bearer token', async () => {
      const response = await request(app)
        .post('/webhook/pamsignal')
        .set('Authorization', `Bearer ${SECRET}`)
        .send(validPayload);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('status', 'success');
    });

    it('should allow requests if WEBHOOK_SECRET is not set', async () => {
      delete process.env.WEBHOOK_SECRET;

      const response = await request(app)
        .post('/webhook/pamsignal')
        .send(validPayload);

      expect(response.status).toBe(200);

      // Restore secret for subsequent tests
      process.env.WEBHOOK_SECRET = SECRET;
    });
  });

  describe('Payload Validation', () => {
    it('should reject empty payloads', async () => {
      const response = await request(app)
        .post('/webhook/pamsignal')
        .set('Authorization', `Bearer ${SECRET}`)
        .send({});

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'Bad Request: Invalid payload format');
    });

    it('should reject payloads missing the event object', async () => {
      const response = await request(app)
        .post('/webhook/pamsignal')
        .set('Authorization', `Bearer ${SECRET}`)
        .send({
          pamsignal: { attempts: 1 }
        });

      expect(response.status).toBe(400);
    });
  });

  describe('Event Handling', () => {
    it('should successfully process a login_success event', async () => {
      const response = await request(app)
        .post('/webhook/pamsignal')
        .set('Authorization', `Bearer ${SECRET}`)
        .send({
          event: { action: 'login_success' },
          user: { name: 'admin' },
          source: { ip: '10.0.0.1' },
          host: { hostname: 'server-01' },
          process: { pid: 1234 },
          pamsignal: { event_type: 'LOGIN_SUCCESS' }
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('message', 'Event received');
    });
  });
});
