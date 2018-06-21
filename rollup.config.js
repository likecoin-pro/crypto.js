// rollup.config.js
import babel from 'rollup-plugin-babel';
import resolve from 'rollup-plugin-node-resolve';
import commonjs from 'rollup-plugin-commonjs';
import uglify from 'rollup-plugin-uglify';

const getBuild = (minified = false) => ({
    input: 'src/index.js',
    output: [{
        strict: false,
        file: `./dist/bundle${minified ? '.min' : ''}.cjs.js`,
        name: 'LikecoinCryptoJS',
        format: 'cjs'
    }, {
        strict: false,
        file: `./dist/bundle${minified ? '.min' : ''}.iife.js`,
        name: 'LikecoinCryptoJS',
        format: 'iife'
    }],
    plugins: [
        babel({
            exclude: 'node_modules/**',
            runtimeHelpers: false
        }),
        resolve(),
        commonjs(),
        minified ? uglify() : () => null
    ]
});

export default [
    getBuild(),
    getBuild(true)
];