# call scripts

## abstruct

ptarmd call `install/<NODE DIR>/scripts/*.sh` on event happens.

1. [started.sh](#startedsh)
2. [connected.sh](#connectedsh)
3. [disconnected.sh](#disconnectedsh)
4. [established.sh](#establishedsh)
5. [payment.sh](#paymentsh)
6. [addfinal.sh](#addfinalsh)
7. [fulfill.sh](#fulfillsh)
8. [fail.sh](#failsh)
9. [htlcchanged.sh](#htlcchangedsh)
10. [closed.sh](#closedsh)
11. [dbclosed.sh](#dbclosedsh)
12. [error.sh](#errorsh)

### started.sh

ptarmd started.

### connected.sh

connected peer node.

### disconnected.sh

disconnected peer node.

### established.sh

channel established.

### payment.sh

* receive payment request from JSON-RPC(including `ptarmcli`)
* routing success

### addfinal.sh

* `update_add_htlc` received and the preimage is mine.
* `revoke_and_ack` message exchanged.

This is useful for faster receiving action.

### fulfill.sh

.

### fail.sh

.

### htlcchanged.sh

`revoke_and_ack` message exchanged.

### closed.sh

channel closed.

### dbclosed.sh

channel closed and remove channel from database.

### error.sh

`error` message received.
