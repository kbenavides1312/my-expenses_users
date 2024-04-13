# use official Golang image
FROM golang:1.22-alpine3.19

# set working directory
WORKDIR /app/users

# Copy the source code
COPY ./src/users-api . 

#EXPOSE the port
EXPOSE 8000

# Run the executable
CMD ["./users-api"]