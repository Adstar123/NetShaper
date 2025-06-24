const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const webpack = require('webpack');

module.exports = {
  mode: process.env.NODE_ENV || 'development',
  entry: './src/renderer/index.tsx',
  target: 'electron-renderer',
  devtool: 'source-map',
  module: {
    rules: [
      {
        test: /\.(ts|tsx)$/,
        exclude: /node_modules/,
        use: {
          loader: 'ts-loader'
        }
      },
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader']
      },
      {
        test: /\.(png|jpe?g|gif|svg)$/i,
        use: [
          {
            loader: 'file-loader',
            options: {
              name: '[name].[ext]',
              outputPath: 'assets'
            }
          }
        ]
      }
    ]
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
    fallback: {
      "path": false,
      "fs": false,
      "crypto": false,
      "stream": false,
      "util": false,
      "buffer": false,
      "assert": false,
      "events": false,
      "querystring": false,
      "url": false,
      "http": false,
      "https": false,
      "os": false,
      "tty": false
    }
  },
  output: {
    filename: 'renderer.js',
    path: path.resolve(__dirname, 'dist')
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: './src/renderer/index.html'
    }),
    new webpack.DefinePlugin({
      'global': 'window',
    })
  ],
  devServer: {
    port: 9000,
    host: '127.0.0.1',
    allowedHosts: 'all',
    headers: {
      'Access-Control-Allow-Origin': '*'
    },
    client: false,
    hot: false,
    liveReload: false
  }
};