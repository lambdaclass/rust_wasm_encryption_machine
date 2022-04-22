wasm_test:
	cargo test --target wasm32-unknown-unknown

test:
	cargo test

build:
	wasm-pack build --target web
