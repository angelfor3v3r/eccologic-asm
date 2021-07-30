const HtmlWebpackPlugin = require( "html-webpack-plugin" );
const CompressionPlugin = require( "compression-webpack-plugin" );
const zlib              = require( "zlib" );
const path              = require( "path" );

module.exports = {
    context: path.resolve( __dirname, "src" ),
    entry: "./index.js",
    output: {
        path: path.resolve( __dirname, "../bin/site" ),
        filename: "bundle.js"
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