## How to use

### CLi

switch to your directory then run main.go
```bash
go run main.go
```

### Execute file for windows

FileCrypto.exe is packaged for windows 11, if it not work on earlier version windows or other OS, you can re-build it by yourself.

```bash
go build main.go
```

## How it work

When you execute main.go, it will listen your 8080 port with routes on POST or GET method

- POST: /file/upload
- GET: /file/upload/{encrypt-string}

### Upload

When You upload file success, you will get a encrypt string like:

```text
e6cfddb6c08803f7d6f4f9675df3e9fc3e4278d4
```

Server side will record this encrypt string and mapping it's upload file name in file_map.json

### Download

When you download with encrypt string, server will find out and decrypt it then transfer to you with upload file name.
