# ptarmigan-api

[ptarmigan rest-api](https://github.com/nayutaco/ptarmigan) Lightning Network implementation ptarmigan REST-API

## Configration


```
# copy .env file
$ cd $INSTALL_DIR/ptarmigan/ptarmapi/
$ cp.env-sample .env

# edit .env change to your environment
$ vi .env
```


## Installation

```bash
$ cd $INSTALL_DIR/ptarmigan/ptarmapi/
$ sudo apt-get install npm
$ npm install
```

## Running the app

```bash
# start development mode
$ npm run start
```

## Example
```
$ curl -X POST "http://localhost:3000/getinfo" -H "accept: application/json"
```

## Browser of local PC

Use this rest-api in a closed network.
Use ssh port forwarding without exposing the port.

```
# ssh port foward from localhost 3333 to server 3000
$ ssh user@ipaddress -L 3333:localhost:3000
# access to ptarmigan rest-api OpenAPI(swagger) http://localhost:3333/api
```
