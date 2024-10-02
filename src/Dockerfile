FROM golang:1.22.2-alpine AS builder
RUN apk add --no-cache git 

WORKDIR /app

COPY . .

RUN go mod download && go build -o main ./main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates bash vim postgresql-client
WORKDIR /root/
COPY --from=builder /app/main .
COPY --from=builder /app/bash/main.sh ./bash/main.sh
COPY --from=builder /app/bash/init.sql ./bash/init.sql
RUN chmod +x ./bash/main.sh

EXPOSE 8080

CMD ["bash", "-c", "./bash/main.sh && ./main"]