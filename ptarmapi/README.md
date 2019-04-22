# ptarmigan-api

[ptarmigan rest-api](https://github.com/nayutaco/ptarmigan) Lightning Network implementation ptarmigan REST-API

## Configration

```
# edit .env file
ptarmigan/ptarmapi/.env
```

## Installation

```bash
$ sudo apt-get install npm
$ npm install
```

## Running the app

```bash
# start development mode
$ npm run start
```

## 
```
curl -X POST "http://localhost:3000/getinfo" -H "accept: application/json"
```

## browser

```
# ssh port foward from localhost 3333 to server 3000
ssh user@ipaddress -L 3333:localhost:3000
access to http://localhost:3333/api
```
