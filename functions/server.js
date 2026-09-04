const serverless = require('serverless-http');
const app = require('../server');

// Wrap with serverless-http
const handler = serverless(app, {
  request(request, event) {
    // Netlify passes the full path: /.netlify/functions/server/api/auth/login
    // Express expects:                                          /api/auth/login
    // Strip the function prefix so routes match correctly.
    const raw = event.path || request.url || '/';
    const PREFIX = '/.netlify/functions/server';
    request.url = raw.startsWith(PREFIX) ? raw.slice(PREFIX.length) || '/' : raw;
  }
});

module.exports.handler = async (event, context) => {
  // Prevent Netlify from waiting for the event loop to drain
  context.callbackWaitsForEmptyEventLoop = false;
  return handler(event, context);
};
