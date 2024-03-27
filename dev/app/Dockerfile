FROM golang:latest

WORKDIR /app

COPY go.mod ./
RUN go mod download

RUN go build -o /authentication_service/cmd

EXPOSE 8080

CMD ["/authentication_service/cmd"]