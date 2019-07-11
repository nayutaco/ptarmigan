# About invoice notifications api

This api notify to client when change invoice status.

- `unused -> used`: notify to client(status has changed from unused to used).
- `unused -> unused`: not notify to client(status still unused).

API use [WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API), receive notifications in real time.


## How it works

```
addfinal.sh -> notification/addfinal(ptarmigan rest api) -> cache for paymenthash -> htlcchanged.sh -> notification/htlcchanged(ptarmigan rest api) -> WebSocket(use cached paymenthash) -> notify to client(status, paymenthash...etc)
```


## Installation

require: [How to use Ptarmigan REST API](./howtouse_rest_api.md)

```bash
$ sudo apt install -y curl
```


## Configration

Be sure to specify the following environment variables before starting Ptarmigan.

```
export NODE_NAME="name"

ex) export NODE_NAME="node"
```


## Running the app

```bash
# start development mode
$ npm run start
```


## URL

Default url is `ws://127.0.0.1:3000/ws`.


## Debug

This html connected to invoice notifications api.

Please use it for connection test.

[index.html](https://github.com/nayutaco/ptarmigan/blob/master/ptarmapi/test/client/index.html)


## FAQ

###  No such file or directory

If you get this message...

```
cp: /ptarmigan/ptarmapi/script/htlcchanged.sh: No such file or directory
```

```
cp: /ptarmigan/ptarmapi/script/addfinal.sh: No such file or directory
```

#### Case1

Please check if there is `/ptarmigan/install/${NODE_NAME}/script`.

#### Case2

Please modify the file path of `cp` in this bash file.

`cp /ptarmigan/ptarmapi...` 

https://github.com/nayutaco/ptarmigan/blob/master/ptarmapi/script/set_addfinal.sh

https://github.com/nayutaco/ptarmigan/blob/master/ptarmapi/script/set_htlcchanged.sh


### -bash: Permission denied

If you get this message...

```
-bash: ./~.sh: Permission denied
```

Please chmod.

```
chmod +x ~.sh
```