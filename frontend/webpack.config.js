const path              = require( "path" );
const zlib              = require( "zlib" );
const TerserPlugin      = require( "terser-webpack-plugin" );
const HtmlWebpackPlugin = require( "html-webpack-plugin" );
const CompressionPlugin = require( "compression-webpack-plugin" );

module.exports = {
    context: path.resolve( __dirname, "src" ),
    entry: "./index.js",
    output: {
        path: path.resolve( __dirname, "../bin/site" ),
        publicPath: "/",
        filename: "bundle.js"
    },
    resolve: {
        alias: {
            "react": "preact/compat",
            "react-dom": "preact/compat"
        }
    },
    module: {
        rules: [
            {
                test: /\.jsx?$/,
                exclude: /node_modules/,
                use: "babel-loader"
            }
        ]
    },
    optimization: {
        minimize: true,
        minimizer: [
            new TerserPlugin({
                parallel: true,
                extractComments: false,
                terserOptions: {
                    format: {
                        comments: false
                    }
                }
            })
        ]
    },
    plugins: [
        new HtmlWebpackPlugin({
            template: "./index.ejs"
        }),
        new CompressionPlugin({
            filename: "[path][base].gz",
            algorithm: "gzip",
            test: /\.(js|css|html|svg)$/,
            threshold: 2048
        }),
        new CompressionPlugin({
            filename: "[path][base].br",
            algorithm: "brotliCompress",
            test: /\.(js|css|html|svg)$/,
            compressionOptions: {
                params: {
                    [zlib.constants.BROTLI_PARAM_QUALITY]: 11,
                },
            },
            threshold: 2048
        })
    ]
};