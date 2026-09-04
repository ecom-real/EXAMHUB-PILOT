const serverless = require('serverless-http');
const app = require('../server');

// Wrap with serverless-http
// basePath strips the Netlify function prefix so Express routes match correctly
const handler = serverless(app, {
  request(request, event) {
    // Ensure the path is what Express expects (/api/...)
    // Netlify passes the full path including function prefix sometimes
    request.url = event.path || request.url;
  }
});

module.exports.handler = async (event, context) => {
  // Prevent Netlify from waiting for the event loop to drain
  context.callbackWaitsForEmptyEventLoop = false;
  return handler(event, context);
};
