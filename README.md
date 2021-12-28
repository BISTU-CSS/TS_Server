# TimeStamp_Server

1.install gflags
git clone git@github.com:BISTUCSS/gflags.git --recursive

export CXXFLAGS="-fPIC" && cmake . && make VERBOSE=1

make && make install