FROM perl

# install mysql drivers.
RUN cpanm DBD::mysql
RUN cpanm Test2::V0;

COPY simple.t /

CMD prove simple.t
