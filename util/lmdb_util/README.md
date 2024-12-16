# lmdb_util
    lmdb_util can be used to create ja3 db from json file or can be used to debug the existing db.
    lmdb util has two modes.
        - Read mode 
        - write mode
    Read mode is used to dump/print all keys in the existing db or print memory stats about the db
    Write mode is used to create db from json or to get a value a single ja3 key from an existing db.


## Commands

# Create db from json
```sh
    lmdb_util -w -d ~/gitrepo/waflz/tmp_db -m 314572800 -l -j ~/gitrepo/lmdb-ja3/test_data/small_data.json 
```

# Get singlekey from db 
```sh
    lmdb_util -w -d ~/gitrepo/waflz/tmp_db -m 314572800 --g -k 253714f62c0a1e6869fe8ba6a45a0588:custom_bot_score
```

# Dump all the keys in db
```sh
    lmdb_util -r -d ~/gitrepo/waflz/tmp_db -p
```

# Dump stats of db
```sh
    lmdb_util -r -d ~/gitrepo/waflz/tmp_db -s
```





