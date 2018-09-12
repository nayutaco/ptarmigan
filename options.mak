#GNU_PREFIX := arm-linux-gnueabihf-

# 0:mainnet, 1:testnet
NETKIND=1

# 0:not SPV 1:SPV
USE_SPV=0

# build ptarmd(WARNING: if you change this setting, need rebuild)
#   EXEC
#     as process
#   LIB
#     as library
BUILD_PTARMD=EXEC

# 0: enable print func 1:disable
#  priority higher than PTARM_USE_PRINTFUNC
DISABLE_PRINTFUND=0

# 0: disable developer mode 1:enable
ENABLE_DEVELOPER_MODE=0

# 0: log to file 1: stdout
ENABLE_PLOG_TO_STDOUT_PTARMD=0

# max channels("conntct to"(MAX_CHANNELS) and "conect from"(MAX_CHANNELS))
MAX_CHANNELS=10
