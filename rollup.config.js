// rollup.config.js
import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import uglify from 'rollup-plugin-uglify';

const getBuild = (minified = false) => ({
    input: 'main.js',
    output: [{
        file: `./dist/bundle${minified ? '.min' : ''}.cjs.js`,
        name: 'LikecoinCryptoJS',
        format: 'cjs'
    }, {
        file: `./dist/bundle${minified ? '.min' : ''}.iife.js`,
        name: 'LikecoinCryptoJS',
        format: 'iife'
    }],
    plugins: [
        resolve(),
        commonjs(),
        minified ? uglify() : () => null
    ]
});

export default [
    getBuild(),
    getBuild(true)
];