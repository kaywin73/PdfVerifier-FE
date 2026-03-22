wasm-pack build --target web

wasm-pack build --target web -- --features dev and verify output.

wasm-pack build --target web -- --features prod and verify output.



What this does:

Compiles your Rust code into WebAssembly.

Generates the JavaScript "glue" code in the pkg/ directory.

Optimizes the WASM binary for the web.

After running this, your main.js (which currently imports from ./pkg/pdfverifier\_fe.js) will be able to use the updated logic.





npm run build:dev 

npm run build:prod

