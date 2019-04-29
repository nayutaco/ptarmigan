export default {
    ptarmdPath: process.env.PTARMD_PATH || '~/work/ptarmigan/install',
    ptarmdNodePath: process.env.PTARMD_NODE_PATH || '~/work/ptarmigan/install/node',
<<<<<<< HEAD
    ptarmdRpcPort: process.env.PTARMD_RPC_PORT || 9736,
    ptarmdHost: process.env.PTARMD_HOST || 'localhost',
    bitcoindRpcPort: process.env.BITCOIND_RPC_PORT || 18332,
=======
    ptarmdPort: process.env.PTARMD_PORT || 9736,
    ptarmdHost: process.env.PTARMD_HOST || 'localhost',
    bitcoindPort: process.env.BITCOIND_PORT || 18332,
>>>>>>> upstream/master
    bitcoindHost: process.env.BITCOIND_HOST || 'localhost',
    bitcoindUser: process.env.BITCOIND_USER || 'bitcoinuser',
    bitcoindPassword: process.env.BITCOIND_PASSWORD || 'bitcoinpassword',
};
