FROM debian:stable

WORKDIR /code

RUN apt update -y && apt full-upgrade -y && apt install -y g++ vim man && apt clean && rm -rf /var/lib/apt/lists/*

COPY ./code .

CMD sh -c "tail -f /dev/null"