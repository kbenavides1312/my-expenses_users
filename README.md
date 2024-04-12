# my-expenses.users

create development image
```
docker build --file Dockerfile.dev --tag users-api:dev .
```

start dev db
```
docker run --rm \
    --name go-db \
    -v ./data:/var/lib/postgresql/data \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=postgres \
    -e POSTGRES_DB=postgres \
    -p 5432:5432 \
    -d postgres:12
```

inspect db ip
```
docker inspect --format '{{ .NetworkSettings.IPAddress }}' go_db
```

start development container (replace host ip by the one from previous step)

```
docker run --rm -d \
--name users-api-dev \
-p 8080:8000 \
-e DATABASE_URL="host=172.17.0.2 user=postgres password=postgres dbname=postgres sslmode=disable" \
-v "$PWD/src":/app/users \
-v "$PWD/dependencies/go":/go \
users-api:dev
```

Inside dev container initialize go module
```
go mod init main
```

install modules and requirements
```
go mod tidy
```

run application
```
go run main.go
```

build binary
```
go build -o users-api .
```

build local api image
```
docker build --file Dockerfile --tag users-api:local . 
```

start local user api
```
docker run --rm -d \
--name users-api \
-p 8080:8000 \
-e DATABASE_URL="host=172.17.0.2 user=postgres password=postgres dbname=postgres sslmode=disable" \
users-api:local
```

test get request
```
curl http://localhost:8080/api/users
```

create an user
```
curl -X POST http://localhost:8080/api/users \
--header 'Content-Type: application/json' \
--data-raw '{"name": "aaa","email": "aaa@mail"}'
```
