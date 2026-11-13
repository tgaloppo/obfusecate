# start daemon
build/cryptofs_daemon vault.arcane ~/.ssh/vault.key /tmp/bridge -f

# create and mount filesystem
truncate -s 100M /tmp/bridge/data 
mkfs.ext4 -F -O ^has_journal -E root_owner=$(id -u):$(id -g) /tmp/bridge/data
fuse2fs /tmp/bridge/data ~/secure
...
fusermount3 -u ~/secure

