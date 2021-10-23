FROM perl

# install mysql drivers.
RUN cpanm DBD::mysql
RUN cpanm Test2::V0;

COPY *.t /

CMD prove *.t
