FROM golang:1.14.3-alpine 

WORKDIR /app
COPY . /app
ENV GO111MODULE=on
RUN go build -o ./bin/vtun ./main.go

ENTRYPOINT ["./bin/vtun"]

