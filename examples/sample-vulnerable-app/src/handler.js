const fs = require('fs');
const mongoose = require('mongoose');

const User = mongoose.model('User', new mongoose.Schema({ name: String, role: String }));

exports.handler = async (event) => {
  // VULN: logs full event — may contain auth tokens, secrets, PII
  console.log(event);

  // VULN: no input validation — body used directly in a database query
  const body = JSON.parse(event.body);
  const users = await User.find(body.query);

  // VULN: writing to /tmp without cleanup — disk exhaustion in Lambda
  fs.writeFileSync('/tmp/last-query.json', JSON.stringify(body));

  // VULN: sensitive data in response without field filtering
  return {
    statusCode: 200,
    headers: {
      // VULN: permissive CORS
      'Access-Control-Allow-Origin': '*',
    },
    body: JSON.stringify(users),
  };
};
