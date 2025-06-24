const path = require('path');

module.exports = {
  mode: process.env.NODE_ENV || 'development',
  entry: {
    main: './src/main/main.ts',
    preload: './src/main/preload.ts'
  },
  target: 'electron-main',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js'
  },
  module: {
    rules: [
      {
        test: /\.ts$/,
        exclude: /node_modules/,
        use: {
          loader: 'ts-loader'
        }
      },
      {
        test: /\.node$/,
        loader: 'node-loader'
      }
    ]
  },
  resolve: {
    extensions: ['.ts', '.js', '.node']
  },
  externals: {
    '../../build/Release/network.node': 'commonjs ../../build/Release/network.node'
  }
};