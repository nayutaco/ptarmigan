# How to use Ptarmigan REST API

[Ptarmigan REST API](../ptarmapi) Lightning Network implementation Ptarmigan REST API

## Configuration


```
# copy .env file
$ cd $INSTALL_DIR/ptarmigan/ptarmapi/
$ cp .env-sample .env

# edit .env change to your environment
$ vi .env
```


## Installation

```bash
$ cd $INSTALL_DIR/ptarmigan/ptarmapi/
$ sudo apt-get install npm
$ npm install
```

If use `invoice notifications api`, please install this.

[What's invoice notifications api](./about_invoice_notifications.md)

```bash
$ sudo apt install -y curl
```


## Running the app

```bash
# start development mode
$ npm run start
```

Not use invoice notifications.

```bash
$ npm run start:not-use-invoices-notification
```


## Example

Default API token is `ptarmigan`.

```
$ curl -X POST "http://localhost:3000/getinfo" -H "accept: application/json/" -H "Authorization: Bearer ptarmigan"
```


## Browser of local PC

Use this rest-api in a closed network.
Use ssh port forwarding without exposing the port.

```
# ssh port forward from localhost 3333 to server 3000
$ ssh user@ipaddress -L 3333:localhost:3000
# access to ptarmigan rest-api OpenAPI(swagger) http://localhost:3333/api
```
