# rust_wasm_playground

# How to run


Run the following command in the terminal:

```
wasm-pack build --target web
```

and then run an http server (e.g. a python server):

```
python3 -m http.server
```

finally, open the browser and go (replace the port number with the one you used):

```
127.0.0.1:PORT/index.html
```
