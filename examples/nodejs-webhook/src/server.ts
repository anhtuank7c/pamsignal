import * as dotenv from 'dotenv';
// Load environment variables before anything else
dotenv.config();

import app from './app';

const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

app.listen(PORT, () => {
  console.log(`🚀 PAMSignal Webhook Receiver listening on port ${PORT}`);
  console.log(`URL: http://localhost:${PORT}/webhook/pamsignal`);
  
  if (!WEBHOOK_SECRET) {
    console.log('⚠️  WARNING: Running without authentication. Set WEBHOOK_SECRET in .env');
  }
});
