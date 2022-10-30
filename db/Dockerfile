FROM postgres:14
RUN apt-get update && apt-get install wget -y
RUN wget https://github.com/PostgREST/postgrest/releases/download/v10.1.0/postgrest-v10.1.0-linux-static-x64.tar.xz
RUN tar -xf postgrest*.tar.xz && mv ./postgrest /usr/bin
RUN mkdir /app
RUN useradd -ms /bin/bash transontario
COPY ./*.sql /app
COPY ./*.sh /app
COPY ./postgrest.conf /app
RUN chown -R transontario /app
USER transontario
RUN cd /app && ./init.sh
CMD cd /app && ./start.sh
EXPOSE 3000

