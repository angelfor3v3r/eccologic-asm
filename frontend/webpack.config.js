const HtmlWebpackPlugin = require( "html-webpack-plugin" );
const CompressionPlugin = require( "compression-webpack-plugin" );
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
        })
    ]
};