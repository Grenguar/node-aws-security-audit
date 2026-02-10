const webpack = require('webpack');

module.exports = {
  entry: './src/server.js',
  target: 'node',

  // VULN: source maps in production — exposes original source code
  devtool: 'source-map',

  plugins: [
    // VULN: leaks ALL env vars (secrets, DB creds) into the bundle
    new webpack.DefinePlugin({
      'process.env': JSON.stringify(process.env),
    }),
  ],

  // VULN: dev server config shipped to production
  devServer: {
    port: 9000,
    open: true,
  },
};
